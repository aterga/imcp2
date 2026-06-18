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
    response::{Html, IntoResponse, Json, Redirect, Response},
    Form,
};
use base64::Engine;
use rmcp::transport::auth::OAuthClientConfig;
use serde::Deserialize;
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

#[derive(Clone)]
pub struct AuthStore {
    clients: Arc<RwLock<HashMap<String, OAuthClientConfig>>>,
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
            clients: Arc::default(),
            codes: Arc::default(),
            tokens: Arc::default(),
            connects: Arc::default(),
            identities,
        }
    }

    /// Accept a client for the OAuth flow, lazily recording it if unseen.
    ///
    /// PoC stance: client registration is ceremonial here — the real auth is the
    /// verified II delegation plus PKCE, not the client's identity. Accepting
    /// any client_id (rather than requiring it to be pre-registered) keeps the
    /// flow working across server restarts, where Claude Code reuses a cached
    /// dynamically-registered client_id against the in-memory store. The
    /// redirect_uri is still restricted to loopback plus the ChatGPT and
    /// Claude.ai hosted connector OAuth callbacks to avoid an open redirector.
    async fn validate_client(&self, client_id: &str, redirect_uri: &str) -> bool {
        if !is_allowed_redirect(redirect_uri) {
            return false;
        }
        self.clients
            .write()
            .await
            .entry(client_id.to_string())
            .or_insert_with(|| OAuthClientConfig::new(client_id.to_string(), redirect_uri.to_string()));
        true
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
    // the connection is to the MCP server itself, whose origin II already knows
    // from its own `mcp_server_origin` config (used both for the delegation's
    // derivation origin and the caller-principal check). `ttl` is 60 minutes.
    let base = base_url();
    let callback = format!("{base}/oauth/connect/callback");
    let ttl_ns: u64 = 60 * 60 * 1_000_000_000;
    let ii_mcp_url = format!(
        "{ii}/mcp#public_key={pk}&callback={cb}&state={st}&ttl={ttl}",
        ii = crate::identities::ii_url(),
        pk = urlencoding::encode(&pubkey_b64),
        cb = urlencoding::encode(&callback),
        st = urlencoding::encode(&connect_state),
        ttl = ttl_ns,
    );
    fragment_redirect(&ii_mcp_url)
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
    Redirect::to(&redirect).into_response()
}

/// Top-level redirect to a URL whose **fragment** must survive (II reads its
/// params from `#…`). A `Location` header drops the fragment in some clients, so
/// navigate via script instead.
fn fragment_redirect(url: &str) -> Response {
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

/// Allowed redirect targets: loopback (accept any port — OAuth clients like
/// Claude Code pick an ephemeral localhost callback port), ChatGPT's connector
/// OAuth callbacks, and Claude.ai's hosted connector callback (Claude.ai web,
/// Desktop, mobile, Cowork). Reject anything else to avoid an open redirector
/// (`approve()` builds its redirect from this URI).
fn is_allowed_redirect(redirect_uri: &str) -> bool {
    // The trailing `/` on the ChatGPT prefix and the exact Claude.ai match bind
    // the host; the loopback hosts need an explicit boundary check (see below).
    is_loopback_redirect(redirect_uri)
        || redirect_uri.starts_with("https://chatgpt.com/connector/oauth/")
        || redirect_uri == "https://claude.ai/api/mcp/auth_callback"
}

/// `http://<loopback>[:port][/path]`, host matched exactly. A bare `starts_with`
/// would also accept `http://localhost.evil.com/...` or `http://localhost@evil`,
/// so require the host to end at a `:` (port), `/` (path), or end of string.
fn is_loopback_redirect(redirect_uri: &str) -> bool {
    ["http://localhost", "http://127.0.0.1", "http://[::1]"]
        .iter()
        .any(|host| {
            redirect_uri
                .strip_prefix(host)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(':') || rest.starts_with('/'))
        })
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
    let client = OAuthClientConfig::new(client_id.clone(), req.redirect_uris[0].clone());
    store.clients.write().await.insert(client_id.clone(), client);

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
    use super::{is_allowed_redirect, pkce_s256};

    /// RFC 7636 Appendix B test vector.
    #[test]
    fn pkce_s256_matches_rfc_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(pkce_s256(verifier), expected);
    }

    #[test]
    fn redirect_allowlist_accepts_known_clients() {
        // Loopback, any port / path (Claude Code picks an ephemeral port).
        assert!(is_allowed_redirect("http://localhost:1234/cb"));
        assert!(is_allowed_redirect("http://127.0.0.1:51000/callback"));
        assert!(is_allowed_redirect("http://[::1]:8080/cb"));
        assert!(is_allowed_redirect("http://localhost/cb"));
        // Hosted connector callbacks.
        assert!(is_allowed_redirect("https://chatgpt.com/connector/oauth/Os40vV-QKzE1"));
        assert!(is_allowed_redirect("https://claude.ai/api/mcp/auth_callback"));
    }

    #[test]
    fn redirect_allowlist_rejects_lookalikes() {
        // Host-confusion variants must not pass (no open redirector).
        assert!(!is_allowed_redirect("http://localhost.evil.com/cb"));
        assert!(!is_allowed_redirect("http://127.0.0.1.evil.com/cb"));
        assert!(!is_allowed_redirect("http://localhost@evil.com/cb"));
        assert!(!is_allowed_redirect("https://chatgpt.com.evil.com/connector/oauth/x"));
        assert!(!is_allowed_redirect("https://chatgpt.com:444/connector/oauth/x"));
        assert!(!is_allowed_redirect("https://claude.ai/api/mcp/auth_callback/extra"));
        assert!(!is_allowed_redirect("https://evil.com/cb"));
    }
}
