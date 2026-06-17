//! OAuth 2.1 authorization server for the MCP endpoint, with **Internet Identity
//! (id.ai)** as the login mechanism. The authorize page logs the user in with
//! `@dfinity/auth-client`; the browser then proves control of its principal by
//! signing a server-issued nonce with the delegation identity. The server
//! verifies the delegation chain (see [`crate::delegation`]) before minting a
//! principal-bound authorization code.
//!
//! Implemented: dynamic client registration, PKCE (S256, enforced), short-lived
//! codes/nonces, 1h access tokens, verified principal binding.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
use rmcp::transport::auth::OAuthClientConfig;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::delegation::{self, SignedDelegation};

const AUTHORIZE_HTML: &str = include_str!("../static/authorize.html");
const CODE_TTL: Duration = Duration::from_secs(120);
const NONCE_TTL: Duration = Duration::from_secs(300);
const TOKEN_TTL: Duration = Duration::from_secs(3600);

/// Public base URL clients use to reach this server. Override with PUBLIC_URL.
pub fn base_url() -> String {
    std::env::var("PUBLIC_URL").unwrap_or_else(|_| "http://localhost:8000".to_string())
}

#[derive(Clone, Default)]
pub struct AuthStore {
    clients: Arc<RwLock<HashMap<String, OAuthClientConfig>>>,
    codes: Arc<RwLock<HashMap<String, CodeGrant>>>,
    tokens: Arc<RwLock<HashMap<String, TokenInfo>>>,
    nonces: Arc<RwLock<HashMap<String, Instant>>>,
}

#[derive(Clone, Debug)]
struct CodeGrant {
    client_id: String,
    scope: Option<String>,
    /// Verified Internet Identity principal.
    principal: String,
    /// Browser/session id minted at approve, set as the `mcp_session` cookie and
    /// carried to the issued token, so the same browser can later be required to
    /// own a domain sign-in.
    session_id: String,
    code_challenge: Option<String>,
    created: Instant,
}

#[derive(Clone, Debug)]
struct TokenInfo {
    principal: String,
    session_id: String,
    created: Instant,
}

impl AuthStore {
    pub fn new() -> Self {
        Self::default()
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

// ---- Nonce: server-issued challenge for the login proof ----------------

/// GET /oauth/nonce — a fresh nonce the browser signs with its II identity.
pub async fn nonce(State(store): State<AuthStore>) -> Response {
    let nonce = Uuid::new_v4().to_string();
    store.nonces.write().await.insert(nonce.clone(), Instant::now());
    Json(json!({ "nonce": nonce })).into_response()
}

// ---- Authorize: serve the II login page --------------------------------

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    #[allow(dead_code)]
    response_type: Option<String>,
    client_id: String,
    redirect_uri: String,
}

/// GET /oauth/authorize — validate the client, then serve the II-login page,
/// which reads remaining OAuth params (state, code_challenge, scope) from
/// `location.search`.
pub async fn authorize(State(store): State<AuthStore>, Query(q): Query<AuthorizeQuery>) -> Response {
    if store.validate_client(&q.client_id, &q.redirect_uri).await {
        // Point the login page at the same II instance used by the app
        // delegation flow (see crate::identities::ii_url).
        let page = AUTHORIZE_HTML.replace("__II_URL__", &crate::identities::ii_url());
        Html(page).into_response()
    } else {
        oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "unknown client_id / redirect_uri")
    }
}

// ---- Approve: verify the II login proof, mint an auth code -------------

#[derive(Debug, Deserialize)]
pub struct ApproveBody {
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    code_challenge: Option<String>,
    nonce: String,
    /// Hex DER of the delegation-chain root public key (the II identity).
    pubkey: String,
    /// Delegation chain as produced by `DelegationChain.toJSON()`.
    delegations: Vec<DelegationJson>,
    /// Hex signature over the nonce by the leaf (session) key.
    signature: String,
}

#[derive(Debug, Deserialize)]
pub struct DelegationJson {
    delegation: DelegationInner,
    signature: String,
}

#[derive(Debug, Deserialize)]
pub struct DelegationInner {
    pubkey: String,
    /// Nanoseconds since epoch, hex-encoded (agent-js bigint form).
    expiration: String,
    #[serde(default)]
    targets: Option<Vec<String>>,
}

/// POST /oauth/approve (JSON) — called by the authorize page after a successful
/// id.ai login. Verifies the delegation chain + nonce signature, then returns
/// the redirect URL carrying a principal-bound authorization code.
pub async fn approve(State(store): State<AuthStore>, Json(body): Json<ApproveBody>) -> Response {
    if !store.validate_client(&body.client_id, &body.redirect_uri).await {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_client", "unknown client / redirect_uri");
    }

    // Consume the nonce (single use, must be fresh).
    match store.nonces.write().await.remove(&body.nonce) {
        Some(issued) if issued.elapsed() < NONCE_TTL => {}
        Some(_) => return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "nonce expired"),
        None => return oauth_err(StatusCode::BAD_REQUEST, "invalid_request", "unknown nonce"),
    }

    let principal = match verify_login_proof(&body) {
        Ok(p) => p.to_text(),
        Err(e) => return oauth_err(StatusCode::UNAUTHORIZED, "access_denied", &e),
    };

    let code = format!("mcp-code-{}", Uuid::new_v4());
    let session_id = format!("sess-{}", Uuid::new_v4());
    store.codes.write().await.insert(
        code.clone(),
        CodeGrant {
            client_id: body.client_id.clone(),
            scope: (!body.scope.is_empty()).then(|| body.scope.clone()),
            principal: principal.clone(),
            session_id: session_id.clone(),
            code_challenge: body.code_challenge.clone(),
            created: Instant::now(),
        },
    );
    tracing::info!(%principal, "verified II login, issued authorization code");

    let mut redirect = format!("{}?code={}", body.redirect_uri, code);
    if !body.state.is_empty() {
        redirect.push_str(&format!("&state={}", body.state));
    }
    // Bind this browser to the session (set during the same-origin approve fetch)
    // so it can later be required to own a domain sign-in. Lax: sent on the
    // first-party top-level GET /signin navigation.
    let cookie = format!(
        "mcp_session={session_id}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400"
    );
    (
        [(axum::http::header::SET_COOKIE, cookie)],
        Json(json!({ "redirect": redirect })),
    )
        .into_response()
}

fn verify_login_proof(body: &ApproveBody) -> Result<candid::Principal, String> {
    let root = hex::decode(&body.pubkey).map_err(|_| "bad pubkey hex")?;
    let sig = hex::decode(&body.signature).map_err(|_| "bad signature hex")?;
    let mut chain = Vec::with_capacity(body.delegations.len());
    for d in &body.delegations {
        let targets = match &d.delegation.targets {
            Some(ts) => Some(
                ts.iter()
                    .map(|t| hex::decode(t).map_err(|_| "bad target hex".to_string()))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            None => None,
        };
        chain.push(SignedDelegation {
            pubkey: hex::decode(&d.delegation.pubkey).map_err(|_| "bad delegation pubkey hex")?,
            expiration: u64::from_str_radix(d.delegation.expiration.trim_start_matches("0x"), 16)
                .map_err(|_| "bad expiration")?,
            targets,
            signature: hex::decode(&d.signature).map_err(|_| "bad delegation signature hex")?,
        });
    }
    let now_ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    delegation::verify_login(body.nonce.as_bytes(), &root, &chain, &sig, now_ns)
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
