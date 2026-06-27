//! OAuth 2.1 authorization server for the MCP endpoint, with **Internet Identity**
//! as the login mechanism. Connecting runs II's `/mcp` delegation flow: the
//! authorize endpoint sends the browser to II with this connection's backend
//! **public** key, and II form-POSTs back a delegation chain `anchor -> backend
//! key` (the 60-minute standing credential). The server verifies the chain (see
//! [`crate::delegation`]) — the chain itself is the proof of identity — stores
//! it, and mints a principal-bound authorization code. No private key is ever
//! transmitted.
//!
//! Implemented: dynamic client registration, PKCE (S256, enforced), short-lived
//! codes, 1h access tokens, verified principal binding.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    body::Body,
    extract::{Query, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Json, Response},
    Form,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::identities::Identities;

const CODE_TTL: Duration = Duration::from_secs(120);
/// How long a started connect (pending II `/mcp` round-trip) stays valid.
const CONNECT_TTL: Duration = Duration::from_secs(600);
const TOKEN_TTL: Duration = Duration::from_secs(3600);

/// Public base URL clients use to reach this server. Override with PUBLIC_URL.
pub fn base_url() -> String {
    std::env::var("PUBLIC_URL").unwrap_or_else(|_| "http://localhost:8000".to_string())
}

/// A registered OAuth client (RFC 7591): the redirect URIs it declared. The
/// authorize flow only redirects a code to one of these (exact match), so the
/// server is not an open redirector and needs no hardcoded host allowlist.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ClientReg {
    redirect_uris: Vec<String>,
}

/// File the dynamic client registrations are persisted to. RFC 7591 clients are
/// long-lived (they cache their `client_id`), so registrations must survive a
/// restart — unlike codes/tokens/sessions, which are short-lived and stay in
/// memory. Override with `OAUTH_CLIENTS_FILE`.
fn clients_file() -> String {
    std::env::var("OAUTH_CLIENTS_FILE").unwrap_or_else(|_| "oauth-clients.json".to_string())
}

fn load_clients() -> HashMap<String, ClientReg> {
    match std::fs::read(clients_file()) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            tracing::warn!("could not parse {}: {e}; starting with no clients", clients_file());
            HashMap::new()
        }),
        // No file yet (first run) is normal and silent; a real read error
        // (permissions, EIO) is logged loudly — it silently drops previously
        // issued client_ids, so it must be diagnosable — but we still start
        // (clients can re-register) rather than refuse to boot.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
        Err(e) => {
            tracing::warn!("could not read {}: {e}; starting with no clients", clients_file());
            HashMap::new()
        }
    }
}

/// Best-effort write-through of the registration store. A failure (e.g. a
/// read-only filesystem) only means registrations don't survive a restart — the
/// client re-registers — so log and carry on.
fn persist_clients(clients: &HashMap<String, ClientReg>) {
    match serde_json::to_vec_pretty(clients) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(clients_file(), bytes) {
                tracing::warn!("could not persist {}: {e}", clients_file());
            }
        }
        Err(e) => tracing::warn!("could not serialize client registrations: {e}"),
    }
}

/// Acceptance rule for a redirect: loopback (any port, RFC 8252 §7.3) or a URI
/// the client registered (exact match, OAuth 2.1).
fn redirect_allowed(reg: Option<&ClientReg>, redirect_uri: &str) -> bool {
    is_loopback_redirect(redirect_uri)
        || reg.is_some_and(|c| c.redirect_uris.iter().any(|u| u == redirect_uri))
}

#[derive(Clone)]
pub struct AuthStore {
    clients: Arc<RwLock<HashMap<String, ClientReg>>>,
    codes: Arc<RwLock<HashMap<String, CodeGrant>>>,
    tokens: Arc<RwLock<HashMap<String, TokenInfo>>>,
    /// Pending connects keyed by the single-use `state` carried through II's
    /// `/mcp` flow (set at authorize, consumed at the callback).
    connects: Arc<RwLock<HashMap<String, PendingConnect>>>,
    /// Shared with the MCP tools: the connect callback stores the standing
    /// credential here, keyed by `session_id`, for the tools to sign with.
    identities: Identities,
}

#[derive(Clone, Debug)]
struct CodeGrant {
    client_id: String,
    scope: Option<String>,
    /// Verified Internet Identity principal.
    principal: String,
    /// Session id minted at authorize and carried to the issued token. It keys
    /// the connection's per-session backend key, standing II credential, and
    /// on-demand per-app account delegations (see `crate::identities`).
    session_id: String,
    code_challenge: Option<String>,
    created: Instant,
}

/// A connect started at `/oauth/authorize`, awaiting the delegation II will
/// form-POST back to `/oauth/connect/callback`.
#[derive(Clone, Debug)]
struct PendingConnect {
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    /// The OAuth client's own `state`, echoed back on the final redirect.
    client_state: String,
    code_challenge: Option<String>,
    /// The connection's session id (its backend key already exists in
    /// `identities`); the standing credential lands here.
    session_id: String,
    created: Instant,
}

#[derive(Clone, Debug)]
struct TokenInfo {
    principal: String,
    session_id: String,
    created: Instant,
}

impl AuthStore {
    pub fn new(identities: Identities) -> Self {
        Self {
            clients: Arc::new(RwLock::new(load_clients())),
            codes: Arc::default(),
            tokens: Arc::default(),
            connects: Arc::default(),
            identities,
        }
    }

    /// Whether `redirect_uri` is acceptable for `client_id`. Per OAuth 2.1 the
    /// redirect must be one the client registered via DCR (exact match) — that,
    /// not a hardcoded host list, is what keeps the server from being an open
    /// redirector and lets any registration-compliant client (Claude, ChatGPT,
    /// Grok, …) connect without code changes. Loopback is the one exception
    /// (RFC 8252 §7.3): native clients bind an ephemeral port at runtime, so
    /// any-port loopback is accepted regardless of the registered port.
    async fn validate_client(&self, client_id: &str, redirect_uri: &str) -> bool {
        redirect_allowed(self.clients.read().await.get(client_id), redirect_uri)
    }

    /// The verified principal + session id behind a bearer token, if valid.
    pub async fn session_for_token(&self, token: &str) -> Option<(String, String)> {
        let tokens = self.tokens.read().await;
        let info = tokens.get(token)?;
        (info.created.elapsed() < TOKEN_TTL).then(|| (info.principal.clone(), info.session_id.clone()))
    }

}

// ---- Authorize: start the II /mcp delegation flow ----------------------

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    #[allow(dead_code)]
    response_type: Option<String>,
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

/// GET /oauth/authorize — validate the client, mint this connection's session
/// (its backend key), and redirect the browser to II's `/mcp` delegation flow,
/// sending the backend **public** key. II will log the user in, then form-POST
/// the delegation chain back to `/oauth/connect/callback`.
pub async fn authorize(State(store): State<AuthStore>, Query(q): Query<AuthorizeQuery>) -> Response {
    if !store.validate_client(&q.client_id, &q.redirect_uri).await {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "unknown client_id / redirect_uri");
    }

    let session_id = format!("sess-{}", Uuid::new_v4());
    let pubkey_b64 = store.identities.session_pubkey_b64(&session_id).await;

    let connect_state = Uuid::new_v4().to_string();
    store.connects.write().await.insert(
        connect_state.clone(),
        PendingConnect {
            client_id: q.client_id.clone(),
            redirect_uri: q.redirect_uri.clone(),
            scope: q.scope.clone().filter(|s| !s.is_empty()),
            client_state: q.state.clone().unwrap_or_default(),
            code_challenge: q.code_challenge.clone(),
            session_id,
            created: Instant::now(),
        },
    );

    // II `/mcp` flow: backend public key out, delegation in. No `app` param —
    // the connection is to the MCP server itself, whose origin II derives from
    // this `callback` URL (used both for the delegation's derivation origin and
    // the per-user trust check against the identity's config). `ttl` is 60 min.
    let base = base_url();
    let callback = format!("{base}/oauth/connect/callback");
    // II's `/mcp` reads `ttl` as MINUTES (it converts to ns canister-side), so
    // send 60, not the nanosecond value.
    let ttl_minutes: u64 = 60;
    let ii_mcp_url = format!(
        "{ii}/mcp#public_key={pk}&callback={cb}&state={st}&ttl={ttl}",
        ii = crate::identities::ii_url(),
        pk = urlencoding::encode(&pubkey_b64),
        cb = urlencoding::encode(&callback),
        st = urlencoding::encode(&connect_state),
        ttl = ttl_minutes,
    );
    js_redirect(&ii_mcp_url)
}

// ---- Connect callback: II form-POSTs the delegation chain here ---------

#[derive(Debug, Deserialize)]
pub struct ConnectCallback {
    /// `DelegationChain.toJSON()` for `anchor -> backend session key`.
    delegation: String,
    /// The single-use connect state set at `/oauth/authorize`.
    state: String,
}

/// POST /oauth/connect/callback — verify and store the standing credential, then
/// redirect the browser back to the OAuth client with a principal-bound code.
pub async fn connect_callback(
    State(store): State<AuthStore>,
    Form(form): Form<ConnectCallback>,
) -> Response {
    let pending = match store.connects.write().await.remove(&form.state) {
        Some(p) if p.created.elapsed() < CONNECT_TTL => p,
        Some(_) => return connect_error("connect request expired — reconnect and try again"),
        None => return connect_error("unknown or already-used connect request"),
    };

    let principal = match store
        .identities
        .accept_standing(&pending.session_id, &form.delegation)
        .await
    {
        Ok(p) => p,
        Err(e) => return connect_error(&format!("could not accept Internet Identity credential: {e}")),
    };

    let code = format!("mcp-code-{}", Uuid::new_v4());
    store.codes.write().await.insert(
        code.clone(),
        CodeGrant {
            client_id: pending.client_id.clone(),
            scope: pending.scope.clone(),
            principal: principal.clone(),
            session_id: pending.session_id.clone(),
            code_challenge: pending.code_challenge.clone(),
            created: Instant::now(),
        },
    );
    tracing::info!(%principal, "captured standing II credential, issued authorization code");

    let mut redirect = format!("{}?code={}", pending.redirect_uri, code);
    if !pending.client_state.is_empty() {
        redirect.push_str(&format!("&state={}", urlencoding::encode(&pending.client_state)));
    }
    // JS navigation, not a 30x: II form-POSTed here, and `form-action` is enforced
    // across redirects, so a `Location` to the client's redirect_uri would be
    // blocked. See `js_redirect`.
    js_redirect(&redirect)
}

/// Top-level redirect via a script-initiated navigation (`location.replace`)
/// rather than an HTTP `Location` header. Two reasons:
///   * the II `/mcp` URL carries its params in the fragment (`#…`), which a
///     `Location` redirect drops in some clients; and
///   * the post-connect hop back to the OAuth client must NOT be a 30x response
///     to II's form POST — browsers enforce `form-action` across redirects, so a
///     `Location` to the client's `redirect_uri` (not in II's `form-action`) is
///     blocked. A fresh JS navigation isn't a form submission, so it's exempt.
fn js_redirect(url: &str) -> Response {
    let safe = url
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('<', "\\x3c");
    Html(format!(
        "<!DOCTYPE html><meta charset=utf-8><script>location.replace(\"{safe}\")</script>"
    ))
    .into_response()
}

fn connect_error(message: &str) -> Response {
    let safe = message.replace('<', "&lt;");
    (
        StatusCode::BAD_REQUEST,
        Html(format!(
            "<!DOCTYPE html><meta charset=utf-8><body style=\"font-family:system-ui;max-width:32rem;margin:3rem auto\"><h1>Could not connect</h1><p>{safe}</p></body>"
        )),
    )
        .into_response()
}

// ---- Token: exchange auth code for an access token ---------------------

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    grant_type: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    code_verifier: Option<String>,
}

/// POST /oauth/token
pub async fn token(State(store): State<AuthStore>, Form(req): Form<TokenForm>) -> Response {
    if req.grant_type != "authorization_code" {
        return oauth_err(StatusCode::BAD_REQUEST, "unsupported_grant_type", "only authorization_code");
    }

    let grant = match store.codes.write().await.remove(&req.code) {
        Some(g) if g.created.elapsed() < CODE_TTL => g,
        Some(_) => return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "code expired"),
        None => return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "unknown or used code"),
    };

    if !req.client_id.is_empty() && req.client_id != grant.client_id {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_client", "client_id mismatch");
    }

    // Enforce PKCE when a challenge was supplied at authorize time.
    if let Some(challenge) = &grant.code_challenge {
        let verifier = match &req.code_verifier {
            Some(v) => v,
            None => return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "code_verifier required"),
        };
        if &pkce_s256(verifier) != challenge {
            return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE verification failed");
        }
    }

    let access_token = format!("mcp-token-{}", Uuid::new_v4());
    store.tokens.write().await.insert(
        access_token.clone(),
        TokenInfo {
            principal: grant.principal.clone(),
            session_id: grant.session_id.clone(),
            created: Instant::now(),
        },
    );
    tracing::info!(principal = %grant.principal, "issued MCP access token");

    let mut body = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL.as_secs(),
    });
    if let Some(scope) = grant.scope {
        body["scope"] = json!(scope);
    }
    Json(body).into_response()
}

/// An `http://` loopback redirect (any port), matched on the parsed **host** so
/// look-alikes can't slip through. Parsing (not `strip_prefix`) is what defends
/// against authority tricks: `http://localhost.evil.com`, `http://localhost@evil.com`,
/// and the userinfo-with-port form `http://localhost:1234@evil.com` all parse to
/// host `evil.com` (or carry userinfo) and are rejected. Userinfo is rejected
/// outright since a legitimate loopback callback never carries credentials.
fn is_loopback_redirect(redirect_uri: &str) -> bool {
    let Ok(url) = url::Url::parse(redirect_uri) else {
        return false;
    };
    url.scheme() == "http"
        && url.username().is_empty()
        && url.password().is_none()
        // host_str() serializes an IPv6 host with brackets ("[::1]").
        && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
}

fn pkce_s256(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

// ---- Dynamic client registration ---------------------------------------

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    #[serde(default)]
    client_name: Option<String>,
    redirect_uris: Vec<String>,
}

/// POST /oauth/register
pub async fn register(State(store): State<AuthStore>, Json(req): Json<RegisterRequest>) -> Response {
    if req.redirect_uris.is_empty() {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "redirect_uris required");
    }
    let client_id = format!("client-{}", Uuid::new_v4());
    // Insert under the lock, then persist a snapshot off the lock (and off the
    // async runtime thread) so disk I/O never blocks readers like
    // `/oauth/authorize`. Registration is infrequent, so the clone is cheap.
    let snapshot = {
        let mut clients = store.clients.write().await;
        clients.insert(
            client_id.clone(),
            ClientReg {
                redirect_uris: req.redirect_uris.clone(),
            },
        );
        clients.clone()
    };
    tokio::task::spawn_blocking(move || persist_clients(&snapshot))
        .await
        .ok();

    // Public client (PKCE, no secret): build the response by hand and OMIT
    // client_secret entirely. Returning client_secret: null breaks clients that
    // validate it as a string; absence correctly signals a public client.
    let mut resp = json!({
        "client_id": client_id,
        "redirect_uris": req.redirect_uris,
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
    });
    if let Some(name) = req.client_name {
        resp["client_name"] = json!(name);
    }
    (StatusCode::CREATED, Json(resp)).into_response()
}

// ---- Discovery metadata -------------------------------------------------

/// GET /.well-known/oauth-authorization-server
///
/// Built by hand rather than via `AuthorizationMetadata` so that absent optional
/// fields are *omitted* — clients (e.g. Claude Code) validate this document and
/// reject `null` where they expect an array (`scopes_supported` is optional per
/// RFC 8414, so leaving it out is correct).
pub async fn authorization_server_metadata() -> Response {
    let base = base_url();
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    }))
    .into_response()
}

/// GET /.well-known/oauth-protected-resource
pub async fn protected_resource_metadata() -> Response {
    let base = base_url();
    Json(json!({
        "resource": format!("{base}/mcp"),
        "authorization_servers": [base],
    }))
    .into_response()
}

// ---- Bearer-token gate for /mcp -----------------------------------------

/// The verified principal + session id of the authenticated MCP session,
/// injected into request extensions so tools can attribute actions and bind
/// per-session delegated identities.
#[derive(Clone, Debug)]
pub struct AuthedSession {
    pub session_id: String,
}

pub async fn require_token(State(store): State<AuthStore>, mut request: Request<Body>, next: Next) -> Response {
    let token = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::to_owned);

    let session = match token {
        Some(t) => store.session_for_token(&t).await,
        None => None,
    };

    match session {
        Some((principal, session_id)) => {
            tracing::debug!(%principal, %session_id, "authenticated MCP request");
            request.extensions_mut().insert(AuthedSession { session_id });
            next.run(request).await
        }
        None => {
            let challenge = format!(
                "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
                base_url()
            );
            (
                StatusCode::UNAUTHORIZED,
                [(axum::http::header::WWW_AUTHENTICATE, challenge)],
                Json(json!({ "error": "invalid_token" })),
            )
                .into_response()
        }
    }
}

fn oauth_err(status: StatusCode, error: &str, desc: &str) -> Response {
    (status, Json(json!({ "error": error, "error_description": desc }))).into_response()
}

/// Re-export for additional JSON fields.
pub type _JsonValue = Value;

#[cfg(test)]
mod tests {
    use super::{is_loopback_redirect, pkce_s256, redirect_allowed, ClientReg};

    /// RFC 7636 Appendix B test vector.
    #[test]
    fn pkce_s256_matches_rfc_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(pkce_s256(verifier), expected);
    }

    #[test]
    fn redirect_requires_registration_or_loopback() {
        let reg = ClientReg {
            redirect_uris: vec![
                "https://grok.com/connector/oauth/cb".to_string(),
                "https://claude.ai/api/mcp/auth_callback".to_string(),
            ],
        };
        // A hosted redirect is accepted iff this client registered it (exact).
        assert!(redirect_allowed(Some(&reg), "https://grok.com/connector/oauth/cb"));
        assert!(redirect_allowed(Some(&reg), "https://claude.ai/api/mcp/auth_callback"));
        assert!(!redirect_allowed(Some(&reg), "https://grok.com/connector/oauth/other"));
        assert!(!redirect_allowed(Some(&reg), "https://claude.ai/api/mcp/auth_callback/x"));
        // An unregistered / unknown client can't use a hosted redirect.
        assert!(!redirect_allowed(None, "https://grok.com/connector/oauth/cb"));
        // Loopback (RFC 8252) is accepted at any port, even unregistered.
        assert!(redirect_allowed(None, "http://127.0.0.1:51000/callback"));
        assert!(redirect_allowed(None, "http://localhost:1234/cb"));
        assert!(redirect_allowed(None, "http://[::1]:8080/cb"));
    }

    /// Loopback matching is on the parsed host, so authority tricks (suffix,
    /// userinfo, userinfo-with-port) can't redirect a code off-box.
    #[test]
    fn loopback_rejects_lookalikes() {
        assert!(is_loopback_redirect("http://127.0.0.1:51000/callback"));
        assert!(is_loopback_redirect("http://localhost/cb"));
        assert!(is_loopback_redirect("http://[::1]:8080/cb"));
        assert!(!is_loopback_redirect("http://localhost.evil.com/cb"));
        assert!(!is_loopback_redirect("http://127.0.0.1.evil.com/cb"));
        assert!(!is_loopback_redirect("http://localhost@evil.com/cb"));
        // userinfo-with-port bypass: real host is evil.com.
        assert!(!is_loopback_redirect("http://localhost:1234@evil.com/cb"));
        assert!(!is_loopback_redirect("http://127.0.0.1:5000@evil.com/cb"));
        // https is not a loopback scheme; credentials never belong on a callback.
        assert!(!is_loopback_redirect("https://localhost/cb"));
        assert!(!is_loopback_redirect("https://evil.com/cb"));
    }
}
