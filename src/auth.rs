//! Minimal OAuth 2.1 authorization server for the MCP endpoint, adapted from the
//! rmcp `complex_auth_streamhttp` example. The one substantive change: instead of
//! a username/password (or bare "approve") step, the authorize page logs the user
//! in with **Internet Identity (id.ai)** via `@dfinity/auth-client`, and the issued
//! access token is bound to the resulting **principal**.
//!
//! PoC gaps (intentionally minimal — see README roadmap):
//!   * The principal is *asserted* by the browser at /oauth/approve. A production
//!     server MUST verify a signed proof (the II delegation chain) before trusting
//!     it — otherwise a caller could claim any principal. Marked TODO below.
//!   * PKCE `code_challenge` is accepted and passed through but not enforced.
//!   * Tokens/sessions are in-memory and never expire-collected.

use std::{collections::HashMap, sync::Arc};

use axum::{
    body::Body,
    extract::{Form, Query, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Json, Redirect, Response},
};
use rmcp::transport::auth::{AuthorizationMetadata, ClientRegistrationResponse, OAuthClientConfig};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::RwLock;
use uuid::Uuid;

const AUTHORIZE_HTML: &str = include_str!("../static/authorize.html");

/// Public base URL clients use to reach this server. Override with PUBLIC_URL.
pub fn base_url() -> String {
    std::env::var("PUBLIC_URL").unwrap_or_else(|_| "http://localhost:8000".to_string())
}

#[derive(Clone, Default)]
pub struct AuthStore {
    clients: Arc<RwLock<HashMap<String, OAuthClientConfig>>>,
    /// auth code -> pending grant (bound to the II principal)
    codes: Arc<RwLock<HashMap<String, Grant>>>,
    /// access token -> issued grant
    tokens: Arc<RwLock<HashMap<String, Grant>>>,
}

#[derive(Clone, Debug)]
struct Grant {
    client_id: String,
    scope: Option<String>,
    /// The Internet Identity principal that authenticated.
    principal: String,
}

impl AuthStore {
    pub fn new() -> Self {
        Self::default()
    }

    async fn validate_client(&self, client_id: &str, redirect_uri: &str) -> bool {
        self.clients
            .read()
            .await
            .get(client_id)
            .is_some_and(|c| c.redirect_uri.contains(redirect_uri))
    }

    /// The principal behind a bearer token, if valid.
    pub async fn principal_for_token(&self, token: &str) -> Option<String> {
        self.tokens.read().await.get(token).map(|g| g.principal.clone())
    }
}

// ---- Authorize: serve the II login page ---------------------------------

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    #[allow(dead_code)]
    response_type: Option<String>,
    client_id: String,
    redirect_uri: String,
}

/// GET /oauth/authorize — validate the client, then serve the II-login page.
/// The page reads the remaining OAuth params (state, code_challenge, scope)
/// straight from `location.search`, so no server-side templating is needed.
pub async fn authorize(
    State(store): State<AuthStore>,
    Query(q): Query<AuthorizeQuery>,
) -> Response {
    if store.validate_client(&q.client_id, &q.redirect_uri).await {
        Html(AUTHORIZE_HTML).into_response()
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "error_description": "unknown client_id or redirect_uri not registered"
            })),
        )
            .into_response()
    }
}

// ---- Approve: II login succeeded, mint an auth code ---------------------

#[derive(Debug, Deserialize)]
pub struct ApproveForm {
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    state: String,
    /// Principal text from the II identity the browser just authenticated.
    principal: String,
}

/// POST /oauth/approve — called by the authorize page after a successful
/// Internet Identity login. Binds a fresh auth code to the principal and
/// redirects back to the client.
pub async fn approve(State(store): State<AuthStore>, Form(form): Form<ApproveForm>) -> Response {
    if !store.validate_client(&form.client_id, &form.redirect_uri).await {
        return (StatusCode::BAD_REQUEST, "invalid client").into_response();
    }

    // TODO(security): verify a signed II delegation proving ownership of
    // `form.principal` before trusting it. The PoC accepts the asserted value.
    let code = format!("mcp-code-{}", Uuid::new_v4());
    store.codes.write().await.insert(
        code.clone(),
        Grant {
            client_id: form.client_id.clone(),
            scope: if form.scope.is_empty() { None } else { Some(form.scope) },
            principal: form.principal,
        },
    );

    let mut url = format!("{}?code={}", form.redirect_uri, code);
    if !form.state.is_empty() {
        url.push_str(&format!("&state={}", form.state));
    }
    Redirect::to(&url).into_response()
}

// ---- Token: exchange auth code for an access token ----------------------

#[derive(Debug, Deserialize)]
pub struct TokenForm {
    grant_type: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    code_verifier: Option<String>,
}

/// POST /oauth/token
pub async fn token(State(store): State<AuthStore>, Form(req): Form<TokenForm>) -> Response {
    if req.grant_type != "authorization_code" {
        return oauth_err(StatusCode::BAD_REQUEST, "unsupported_grant_type", "only authorization_code");
    }
    // PKCE accepted but not enforced (PoC gap).
    let _ = &req.code_verifier;

    let grant = match store.codes.write().await.remove(&req.code) {
        Some(g) => g,
        None => return oauth_err(StatusCode::BAD_REQUEST, "invalid_grant", "unknown or used code"),
    };

    // Tolerate clients that omit client_id/redirect_uri on the token call.
    if !req.client_id.is_empty() && req.client_id != grant.client_id {
        return oauth_err(StatusCode::BAD_REQUEST, "invalid_client", "client_id mismatch");
    }
    let _ = &req.redirect_uri;

    let access_token = format!("mcp-token-{}", Uuid::new_v4());
    store.tokens.write().await.insert(access_token.clone(), grant.clone());
    tracing::info!(principal = %grant.principal, "issued MCP access token");

    Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": grant.scope,
    }))
    .into_response()
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

    let mut resp = ClientRegistrationResponse::new(client_id, req.redirect_uris);
    resp.client_name = req.client_name;
    (StatusCode::CREATED, Json(resp)).into_response()
}

// ---- Discovery metadata -------------------------------------------------

/// GET /.well-known/oauth-authorization-server
pub async fn authorization_server_metadata() -> Response {
    let base = base_url();
    let mut metadata = AuthorizationMetadata::default();
    metadata.authorization_endpoint = format!("{base}/oauth/authorize");
    metadata.token_endpoint = format!("{base}/oauth/token");
    metadata.registration_endpoint = Some(format!("{base}/oauth/register"));
    metadata.issuer = Some(base.clone());
    metadata.response_types_supported = Some(vec!["code".into()]);
    metadata.code_challenge_methods_supported = Some(vec!["S256".into()]);
    metadata
        .additional_fields
        .insert("grant_types_supported".into(), json!(["authorization_code"]));
    Json(metadata).into_response()
}

/// GET /.well-known/oauth-protected-resource — tells the MCP client which
/// authorization server protects this resource.
pub async fn protected_resource_metadata() -> Response {
    let base = base_url();
    Json(json!({
        "resource": format!("{base}/mcp"),
        "authorization_servers": [base],
    }))
    .into_response()
}

// ---- Bearer-token gate for /mcp -----------------------------------------

pub async fn require_token(
    State(store): State<AuthStore>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let token = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "));

    match token {
        Some(t) if store.principal_for_token(t).await.is_some() => next.run(request).await,
        _ => {
            // Point the client at the protected-resource metadata per MCP spec.
            let challenge = format!(
                "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
                base_url()
            );
            (
                StatusCode::UNAUTHORIZED,
                [(axum::http::header::WWW_AUTHENTICATE, challenge)],
                Json(json!({"error": "invalid_token"})),
            )
                .into_response()
        }
    }
}

fn oauth_err(status: StatusCode, error: &str, desc: &str) -> Response {
    (status, Json(json!({"error": error, "error_description": desc}))).into_response()
}

/// JSON helper re-export for additional fields.
pub type _JsonValue = Value;
