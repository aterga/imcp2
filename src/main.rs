//! Minimal MCP PoC: an MCP server exposing two tools over streamable HTTP that
//! talk to the Internet Computer via ic-agent.
//!
//!   1. `get_candid`   — fetch a canister's Candid interface (`candid:service` metadata).
//!   2. `call_canister` — call any method with textual Candid in, textual Candid out.
//!
//! The LLM only ever deals with textual Candid; encoding/decoding happens here.
//! Calls are anonymous for now (query methods + read-only). Signing comes later.

mod auth;
mod delegation;
mod discover;
mod identities;

use candid::{types::value::IDLArgs, Principal};
use ic_agent::Agent;
use axum::response::IntoResponse;
use identities::Identities;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::{
        streamable_http_server::{session::local::LocalSessionManager, tower::StreamableHttpService},
        StreamableHttpServerConfig,
    },
    schemars, ErrorData as McpError, RoleServer, ServerHandler,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Public IC API boundary node. Anonymous queries/updates go here.
const IC_URL: &str = "https://icp-api.io";

/// Candid references exposed as MCP resources so the client writes correct
/// textual Candid. The textual-syntax cheat sheet is emphasised because every
/// tool here speaks textual Candid; the full type reference backs it up.
const CANDID_TEXTUAL_URI: &str = "candid://textual-syntax";
const CANDID_REFERENCE_URI: &str = "candid://reference";
const CANDID_TEXTUAL_MD: &str = include_str!("../static/candid-textual-syntax.md");
const CANDID_REFERENCE_MD: &str = include_str!("../static/candid-reference.md");

/// Bind address. Honours `$PORT` (set by most PaaS), defaulting to 8000.
fn bind_address() -> String {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8000".to_string());
    format!("0.0.0.0:{port}")
}

/// Hosts allowed in the `Host` header by rmcp's DNS-rebinding protection.
/// Defaults to loopback (good for local dev); when served behind a public URL
/// (tunnel/PaaS), the `PUBLIC_URL` host must be allowed or every `/mcp` request
/// is rejected before the bearer token is even checked.
fn allowed_hosts() -> Vec<String> {
    let mut hosts = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Ok(url) = std::env::var("PUBLIC_URL") {
        if let Some(host) = url.split("://").nth(1).and_then(|r| r.split('/').next()) {
            let host = host.trim();
            if !host.is_empty() {
                hosts.push(host.to_string());
            }
        }
    }
    hosts
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetCandidArgs {
    /// Canister principal, e.g. "ryjl3-tyaaa-aaaaa-aaaba-cai" (the ICP ledger).
    canister_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct CallCanisterArgs {
    /// Target canister principal.
    canister_id: String,
    /// Method name to invoke.
    method: String,
    /// Arguments in textual Candid syntax, e.g. `()` or `(record { owner = principal "..." })`.
    #[serde(default = "default_args")]
    args: String,
    /// If true, perform a read-only `query` call; otherwise an `update` call.
    #[serde(default)]
    is_query: bool,
    /// Which identity to call as: "anonymous" (default), or a domain you've
    /// signed into (see list_identities / sign_in), e.g. "oisy.com".
    #[serde(default = "default_identity")]
    identity: String,
}

fn default_args() -> String {
    "()".to_string()
}

fn default_identity() -> String {
    "anonymous".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct DiscoverCanistersArgs {
    /// A web domain or URL served from the IC, e.g. "oisy.com".
    domain: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct SignInArgs {
    /// The app domain to sign into, e.g. "oisy.com".
    domain: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema, Default)]
struct ListIdentitiesArgs {
    /// Optional: after starting a sign_in, pass that domain here to WAIT (up to
    /// ~55s) for the user to finish, instead of returning immediately.
    #[serde(default)]
    wait_for: Option<String>,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema, Default)]
struct SignOutArgs {
    /// Domain identity to forget, e.g. "oisy.com". Omit to sign out of all.
    #[serde(default)]
    domain: Option<String>,
}

#[derive(Clone)]
struct IcTools {
    agent: Agent,
    identities: Identities,
    tool_router: ToolRouter<IcTools>,
}

#[tool_router]
impl IcTools {
    fn new(agent: Agent, identities: Identities) -> Self {
        Self {
            agent,
            identities,
            tool_router: Self::tool_router(),
        }
    }

    #[tool(
        description = "Fetch the Candid (.did) interface definition of an Internet Computer canister, read from its public `candid:service` metadata."
    )]
    async fn get_candid(
        &self,
        Parameters(GetCandidArgs { canister_id }): Parameters<GetCandidArgs>,
    ) -> Result<CallToolResult, McpError> {
        let principal = match Principal::from_text(&canister_id) {
            Ok(p) => p,
            Err(e) => return Ok(err(format!("invalid canister id: {e}"))),
        };
        match self
            .agent
            .read_state_canister_metadata(principal, "candid:service")
            .await
        {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(did) => Ok(ok(did)),
                Err(e) => Ok(err(format!("metadata is not valid UTF-8: {e}"))),
            },
            Err(e) => Ok(err(format!(
                "could not read candid:service metadata: {e}"
            ))),
        }
    }

    #[tool(
        description = "Call a method on an Internet Computer canister with textual Candid in and out. `identity` selects who you call as: \"anonymous\" (default) or a domain you've signed into via sign_in (e.g. \"oisy.com\") — see list_identities. Set is_query=true for read-only query calls."
    )]
    async fn call_canister(
        &self,
        Parameters(CallCanisterArgs {
            canister_id,
            method,
            args,
            is_query,
            identity,
        }): Parameters<CallCanisterArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let principal = match Principal::from_text(&canister_id) {
            Ok(p) => p,
            Err(e) => return Ok(err(format!("invalid canister id: {e}"))),
        };
        let arg_bytes = match candid_parser::parse_idl_args(&args) {
            Ok(parsed) => match parsed.to_bytes() {
                Ok(b) => b,
                Err(e) => return Ok(err(format!("could not encode args `{args}`: {e}"))),
            },
            Err(e) => return Ok(err(format!("could not parse args `{args}`: {e}"))),
        };

        // Pick the agent: anonymous uses the shared agent; a domain identity
        // builds an agent backed by that domain's delegation (the server signs
        // as the user's account for that app).
        let reply = if identity == "anonymous" {
            raw_call(&self.agent, principal, &method, arg_bytes, is_query).await
        } else {
            let session_id = match authed_session(&ctx) {
                Some(s) => s.session_id,
                None => return Ok(err("a domain identity needs an authenticated session".into())),
            };
            let delegated = match self.identities.delegated_identity(&session_id, &identity).await {
                Ok(d) => d,
                Err(e) => return Ok(err(e)),
            };
            let agent = match Agent::builder().with_url(IC_URL).with_identity(delegated).build() {
                Ok(a) => a,
                Err(e) => return Ok(err(format!("could not build agent: {e}"))),
            };
            raw_call(&agent, principal, &method, arg_bytes, is_query).await
        };

        let reply_bytes = match reply {
            Ok(b) => b,
            Err(e) => return Ok(err(format!("call failed: {e}"))),
        };
        // Decode against the canister's Candid interface so field names are recovered.
        Ok(ok(self.decode_reply(principal, &method, &reply_bytes).await))
    }

    #[tool(description = "List the identities you can call as: \"anonymous\" plus every domain you've signed into (principal + remaining validity). After a sign_in, call this with wait_for=<domain> — it waits (~55s) for the user to finish so you can confirm yourself instead of asking them; if it returns still-pending, call again.")]
    async fn list_identities(
        &self,
        Parameters(ListIdentitiesArgs { wait_for }): Parameters<ListIdentitiesArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let session_id = authed_session(&ctx).map(|s| s.session_id).unwrap_or_default();
        let mut pending_note = None;
        if let Some(domain) = wait_for.as_deref() {
            let landed = self
                .identities
                .wait_for_delegation(&session_id, domain, std::time::Duration::from_secs(55))
                .await;
            if !landed {
                pending_note = Some(format!(
                    "\nStill waiting for the user to finish signing in to {domain}. \
                     If they have, call list_identities again with wait_for=\"{domain}\"."
                ));
            }
        }
        let mut out = String::from("Identities (use as `identity` in call_canister):\n");
        for i in self.identities.list(&session_id).await {
            out.push_str(&format!("- {} — {} ({})\n", i.name, i.principal, i.note));
        }
        if let Some(n) = pending_note {
            out.push_str(&n);
        }
        Ok(ok(out))
    }

    #[tool(description = "Sign in to a domain with Internet Identity so you can call canisters as the user's account for that app. Returns a short URL the USER must open in the same browser they signed into this MCP with. After they approve, that domain becomes available as an `identity` in call_canister. Use the same tool to re-sign-in when a delegation expires.")]
    async fn sign_in(
        &self,
        Parameters(SignInArgs { domain }): Parameters<SignInArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        // Accept a bare host or a URL; normalise to the hostname.
        let domain = domain.trim().trim_start_matches("https://").trim_start_matches("http://");
        let domain = domain.split('/').next().unwrap_or(domain).to_string();
        if domain.is_empty() {
            return Ok(err("provide a domain, e.g. oisy.com".into()));
        }
        let session_id = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("sign_in needs an authenticated session".into())),
        };
        let url = self.identities.start_sign_in(&session_id, &domain).await;
        Ok(ok(format!(
            "Ask the user to open this URL in the same browser they used to connect this MCP \
             (it's bound to their session):\n{url}\n\
             Then immediately call list_identities with wait_for=\"{domain}\" — it blocks until \
             they finish, so you confirm it yourself. Do NOT ask the user to tell you when \
             they're done. Once {domain} appears, call_canister with identity=\"{domain}\"."
        )))
    }

    #[tool(description = "Sign out of a domain identity (forget its delegation). Pass a domain to forget that one, or omit to sign out of all. Anonymous always remains.")]
    async fn sign_out(
        &self,
        Parameters(SignOutArgs { domain }): Parameters<SignOutArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let session_id = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("sign_out needs an authenticated session".into())),
        };
        let removed = self.identities.sign_out(&session_id, domain.as_deref()).await;
        Ok(ok(match domain {
            Some(d) if removed > 0 => format!("Signed out of {d}."),
            Some(d) => format!("Was not signed in to {d}."),
            None => format!("Signed out of all {removed} domain identities."),
        }))
    }

    #[tool(
        description = "Discover the Internet Computer canisters behind a web domain (e.g. \"oisy.com\"). Returns every canister id found, with provenance: the `x-ic-canister-id` header (the frontend/asset canister — authoritative), a `/env.json` runtime config (e.g. backend_canister_id), and labelled/bare canister-id literals mined from the JS bundle. There is no authoritative reverse lookup for a site's backend, so results from env.json/bundle are candidates: pick by label (prefer production/IC ids) and confirm with get_candid before calling."
    )]
    async fn discover_canisters(
        &self,
        Parameters(DiscoverCanistersArgs { domain }): Parameters<DiscoverCanistersArgs>,
    ) -> Result<CallToolResult, McpError> {
        match discover::discover(&domain).await {
            Ok(found) if !found.is_empty() => {
                let mut out = format!("Canisters discovered for {domain}:\n");
                for f in &found {
                    out.push_str(&format!(
                        "- {}{} [{}]\n",
                        f.canister_id,
                        f.label.as_deref().map(|l| format!("  — {l}")).unwrap_or_default(),
                        f.sources.join(", "),
                    ));
                }
                out.push_str(
                    "\nThe `header` (x-ic-canister-id) entry is the frontend/asset canister and is \
                     authoritative. Others come from env.json or the JS bundle and may include \
                     multiple environments (prefer the production/IC ids). No authoritative \
                     reverse lookup exists — confirm an interface with get_candid before calling.",
                );
                Ok(ok(out))
            }
            Ok(_) => Ok(ok(format!(
                "No IC canisters found for {domain} — is it served from the Internet Computer?"
            ))),
            Err(e) => Ok(err(e)),
        }
    }
}

impl IcTools {
    /// Decode a reply to textual Candid, preferring the canister's Candid
    /// interface so field names are recovered; fall back to type-less decoding.
    async fn decode_reply(&self, canister: Principal, method: &str, bytes: &[u8]) -> String {
        if let Some(text) = self.decode_with_interface(canister, method, bytes).await {
            return text;
        }
        match IDLArgs::from_bytes(bytes) {
            Ok(decoded) => decoded.to_string(),
            Err(e) => format!("(call succeeded but reply is not decodable as Candid: {e})"),
        }
    }

    /// Type-aware decode: fetch `candid:service`, look up the method's return
    /// types, and decode against them. None if the canister exposes no interface
    /// or anything fails (caller falls back to type-less decoding).
    async fn decode_with_interface(
        &self,
        canister: Principal,
        method: &str,
        bytes: &[u8],
    ) -> Option<String> {
        let raw = self
            .agent
            .read_state_canister_metadata(canister, "candid:service")
            .await
            .ok()?;
        let did = String::from_utf8(raw).ok()?;
        decode_bytes_with_did(&did, method, bytes)
    }
}

/// Decode Candid `bytes` against the return types of `method` declared in the
/// `.did` text, recovering record/variant field names. None if the interface
/// can't be parsed, the method isn't found, or decoding fails.
fn decode_bytes_with_did(did: &str, method: &str, bytes: &[u8]) -> Option<String> {
    let (env, actor) = candid_parser::utils::CandidSource::Text(did).load().ok()?;
    let actor = actor?;
    let func = env.get_method(&actor, method).ok()?;
    let decoded = IDLArgs::from_bytes_with_types(bytes, &env, &func.rets).ok()?;
    Some(decoded.to_string())
}

/// The authenticated MCP session of the calling request, if it carried a valid
/// bearer token (injected by [`auth::require_token`]).
fn authed_session(ctx: &RequestContext<RoleServer>) -> Option<auth::AuthedSession> {
    ctx.extensions
        .get::<axum::http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<auth::AuthedSession>())
        .cloned()
}

fn cookie_value(headers: &axum::http::HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    raw.split(';')
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

/// GET /signin/{link} — consume the single-use link, set a flow cookie, and
/// redirect to II's /mcp delegation flow. The link opens in any browser; the
/// user confirms the verified identity afterward (see `signin_confirm_*`).
async fn signin_redirect(
    axum::extract::State(identities): axum::extract::State<Identities>,
    axum::extract::Path(link): axum::extract::Path<String>,
) -> axum::response::Response {
    match identities.begin_redirect(&link).await {
        Ok((url, flow)) => {
            let cookie = format!(
                "mcp_flow={flow}; Path=/signin; HttpOnly; Secure; SameSite=None; Max-Age=600"
            );
            (
                axum::http::StatusCode::SEE_OTHER,
                [
                    (axum::http::header::LOCATION, url),
                    (axum::http::header::SET_COOKIE, cookie),
                ],
            )
                .into_response()
        }
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, e).into_response(),
    }
}

#[derive(serde::Deserialize)]
struct CallbackForm {
    delegation: String,
    state: String,
}

/// POST /signin/callback — II form-POSTs the delegation here; verify flow cookie
/// + state, stage the verified delegation, then send the browser to the
/// confirmation page (which shows the principal + domain before it lands).
async fn signin_callback(
    axum::extract::State(identities): axum::extract::State<Identities>,
    headers: axum::http::HeaderMap,
    axum::extract::Form(form): axum::extract::Form<CallbackForm>,
) -> axum::response::Response {
    let flow = cookie_value(&headers, "mcp_flow");
    let location = match identities
        .complete_callback(&form.state, flow.as_deref(), &form.delegation)
        .await
    {
        Ok(confirm) => format!(
            "{}/signin/confirm?c={}",
            auth::base_url(),
            urlencoding::encode(&confirm)
        ),
        Err(e) => {
            tracing::warn!("sign-in callback rejected: {e}");
            identities::ii_status_url(false)
        }
    };
    (
        axum::http::StatusCode::SEE_OTHER,
        [(axum::http::header::LOCATION, location)],
    )
        .into_response()
}

#[derive(serde::Deserialize)]
struct ConfirmQuery {
    c: String,
}

/// GET /signin/confirm — show the verified principal + domain and ask the user
/// to explicitly approve connecting it to the requesting assistant session.
async fn signin_confirm_page(
    axum::extract::State(identities): axum::extract::State<Identities>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(q): axum::extract::Query<ConfirmQuery>,
) -> axum::response::Response {
    let flow = cookie_value(&headers, "mcp_flow");
    match identities.confirm_info(&q.c, flow.as_deref()).await {
        Some((principal, domain)) => {
            axum::response::Html(render_confirm_page(&q.c, &principal, &domain)).into_response()
        }
        None => (
            axum::http::StatusCode::BAD_REQUEST,
            "unknown or used confirmation",
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
struct ConfirmForm {
    confirm: String,
}

/// POST /signin/confirm — the user approved; verify the flow cookie, store the
/// delegation under the requesting session, then return to II's status page.
async fn signin_confirm_submit(
    axum::extract::State(identities): axum::extract::State<Identities>,
    headers: axum::http::HeaderMap,
    axum::extract::Form(form): axum::extract::Form<ConfirmForm>,
) -> axum::response::Response {
    let flow = cookie_value(&headers, "mcp_flow");
    let ok = identities.finalize(&form.confirm, flow.as_deref()).await;
    if let Err(e) = &ok {
        tracing::warn!("sign-in confirm rejected: {e}");
    }
    (
        axum::http::StatusCode::SEE_OTHER,
        [(axum::http::header::LOCATION, identities::ii_status_url(ok.is_ok()))],
    )
        .into_response()
}

/// Log each inbound request: method, path (no query string — avoids leaking
/// single-use `?code=`/`?c=` secrets), response status, and latency. Gives
/// visibility into what external MCP clients probe (discovery URLs, unknown
/// paths, etc.) at `RUST_LOG=info`.
async fn log_request(
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let started = std::time::Instant::now();
    let resp = next.run(req).await;
    tracing::info!(
        %method,
        path = %path,
        status = resp.status().as_u16(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "http request"
    );
    resp
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn render_confirm_page(confirm: &str, principal: &str, domain: &str) -> String {
    let domain = html_escape(domain);
    let principal = html_escape(principal);
    let confirm = html_escape(confirm);
    format!(
        r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Confirm sign-in</title></head>
<body style="font-family:system-ui;max-width:32rem;margin:3rem auto;padding:0 1rem;line-height:1.5">
<h2>Confirm sign-in to {domain}</h2>
<p>You signed in as:</p>
<p style="font-family:ui-monospace,monospace;word-break:break-all;background:#f4f4f5;padding:.5rem .75rem;border-radius:.5rem">{principal}</p>
<p>Confirming lets the AI assistant session that requested this sign-in act as this
identity on <b>{domain}</b>. Only continue if <b>you</b> started this from your assistant.</p>
<form method="post" action="/signin/confirm">
<input type="hidden" name="confirm" value="{confirm}">
<button type="submit" style="padding:.6rem 1.2rem;font-size:1rem;border:0;border-radius:.5rem;background:#111;color:#fff;cursor:pointer">Confirm and connect</button>
</form>
<p style="color:#71717a;font-size:.85rem;margin-top:1rem">If you didn't start this, just close this page — nothing will be connected.</p>
</body></html>"#
    )
}

/// Perform a query or update call and return the raw Candid reply bytes.
async fn raw_call(
    agent: &Agent,
    canister: Principal,
    method: &str,
    arg: Vec<u8>,
    is_query: bool,
) -> Result<Vec<u8>, ic_agent::AgentError> {
    if is_query {
        agent.query(&canister, method).with_arg(arg).call().await
    } else {
        agent.update(&canister, method).with_arg(arg).call_and_wait().await
    }
}

#[tool_handler]
impl ServerHandler for IcTools {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder().enable_tools().enable_resources().build(),
        )
        .with_server_info(Implementation::from_build_env())
        .with_instructions(
            "Internet Computer tools. Every tool speaks TEXTUAL Candid — the `(...)` value \
             syntax, e.g. `(record { owner = principal \"aaaaa-aa\"; amount = 5 : nat })`, never \
             the binary form. Before writing Candid args, consult the `candid://textual-syntax` \
             resource (the value syntax these tools use); `candid://reference` has the full type \
             reference. When the user names a website/domain instead of a canister id, use \
             `discover_canisters` to find the canister(s) behind it (frontend via header, \
             backend via env.json/JS bundle). `get_candid` fetches a canister's Candid interface. \
             `call_canister` calls a method with textual Candid in/out, AS an `identity`: \
             \"anonymous\" by default, or a domain the user has signed into. Use \
             `list_identities` to see available identities, and `sign_in(domain)` to add one — \
             it returns a short URL the user opens to authorize via Internet Identity, after \
             which you can call as that domain (e.g. identity=\"oisy.com\")."
                .to_string(),
        )
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult {
            resources: vec![
                RawResource::new(CANDID_TEXTUAL_URI, "Candid textual syntax (used by these tools)")
                    .no_annotation(),
                RawResource::new(CANDID_REFERENCE_URI, "Candid type reference (full spec)")
                    .no_annotation(),
            ],
            next_cursor: None,
            meta: None,
        })
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        let body = match request.uri.as_str() {
            CANDID_TEXTUAL_URI => CANDID_TEXTUAL_MD,
            CANDID_REFERENCE_URI => CANDID_REFERENCE_MD,
            other => {
                return Err(McpError::resource_not_found(
                    "resource_not_found",
                    Some(serde_json::json!({ "uri": other })),
                ))
            }
        };
        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            body,
            request.uri,
        )]))
    }
}

fn ok(text: String) -> CallToolResult {
    CallToolResult::success(vec![Content::text(text)])
}

fn err(text: String) -> CallToolResult {
    CallToolResult::error(vec![Content::text(text)])
}

const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>IC MCP PoC</title></head>
<body style="font-family:system-ui;max-width:40rem;margin:3rem auto">
<h1>Internet Computer MCP PoC</h1>
<p>MCP endpoint: <code>POST /mcp</code></p>
<p>Tools: <code>discover_canisters</code> (domain → canister ids), <code>get_candid</code>, <code>call_canister</code> (as anonymous or a signed-in domain), <code>list_identities</code>, <code>sign_in</code> / <code>sign_out</code> (Internet Identity per domain). All speak textual Candid.</p>
</body></html>"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".to_string().into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    let agent = Agent::builder().with_url(IC_URL).build()?;
    tracing::info!("built ic-agent against {IC_URL}");

    let identities = Identities::new();

    let ct = tokio_util::sync::CancellationToken::new();
    let mcp = {
        let agent = agent.clone();
        let identities = identities.clone();
        StreamableHttpService::new(
            move || Ok(IcTools::new(agent.clone(), identities.clone())),
            LocalSessionManager::default().into(),
            // Stateless + plain-JSON responses: our tools are pure request/response
            // with no server-initiated messages, and this is the most compatible
            // mode across MCP clients (ChatGPT's connector does not complete the
            // stateful SSE/session handshake that the rmcp defaults require).
            StreamableHttpServerConfig::default()
                .with_stateful_mode(false)
                .with_json_response(true)
                .with_cancellation_token(ct.child_token())
                .with_allowed_hosts(allowed_hosts()),
        )
    };

    let store = auth::AuthStore::new();

    // Browser-facing domain sign-in endpoints (II /mcp delegation round-trip).
    let signin = axum::Router::new()
        .route("/signin/{link}", axum::routing::get(signin_redirect))
        .route("/signin/callback", axum::routing::post(signin_callback))
        .route(
            "/signin/confirm",
            axum::routing::get(signin_confirm_page).post(signin_confirm_submit),
        )
        .with_state(identities.clone());

    // /mcp is gated by a bearer token issued after Internet Identity login.
    let protected_mcp = axum::Router::new()
        .nest_service("/mcp", mcp)
        .layer(axum::middleware::from_fn_with_state(
            store.clone(),
            auth::require_token,
        ));

    // OAuth authorization-server + discovery endpoints (CORS-open for clients).
    let cors = tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any);
    let oauth = axum::Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            axum::routing::get(auth::authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            axum::routing::get(auth::protected_resource_metadata),
        )
        // Path-aware discovery locations (RFC 9728 §3.1 / RFC 8414): a resource at
        // `…/mcp` has its metadata at `/.well-known/<doc>/mcp`. Clients vary —
        // Claude/ChatGPT follow the `resource_metadata` hint (the root doc above),
        // but spec-strict clients derive the `/mcp`-suffixed URL. Serve both.
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            axum::routing::get(auth::protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server/mcp",
            axum::routing::get(auth::authorization_server_metadata),
        )
        .route("/oauth/authorize", axum::routing::get(auth::authorize))
        .route("/oauth/nonce", axum::routing::get(auth::nonce))
        .route("/oauth/approve", axum::routing::post(auth::approve))
        .route("/oauth/token", axum::routing::post(auth::token))
        .route("/oauth/register", axum::routing::post(auth::register))
        .layer(cors)
        .with_state(store.clone());

    let app = axum::Router::new()
        .route("/", axum::routing::get(|| async { axum::response::Html(INDEX_HTML) }))
        .merge(signin)
        .merge(oauth)
        .merge(protected_mcp)
        // Log every inbound request (method, path, status, latency) so we can see
        // what external clients actually hit — discovery probes, unknown paths,
        // etc. Only the path is logged, never the query string, so single-use
        // secrets (`?code=`, `?c=`) don't land in logs.
        .layer(axum::middleware::from_fn(log_request));

    let bind = bind_address();
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("listening on http://{bind}  (MCP at /mcp, OAuth at /oauth/*)");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            ct.cancel();
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::decode_bytes_with_did;
    use candid::types::value::IDLArgs;
    use candid_parser::parse_idl_args;

    // Field names are hashed on the Candid wire; decoding against the method's
    // declared return type must recover them (type-less decoding shows hashes).
    #[test]
    fn typed_decode_recovers_field_names() {
        let did = "service : { stats : () -> (record { name : text; url : text }) query }";
        // Encode a record reply (names get hashed in the wire format).
        let bytes = parse_idl_args("(record { name = \"ICP\"; url = \"https://internetcomputer.org\" })")
            .unwrap()
            .to_bytes()
            .unwrap();

        // Type-less decode -> hashed field ids.
        let typeless = IDLArgs::from_bytes(&bytes).unwrap().to_string();
        assert!(!typeless.contains("name ="), "type-less should NOT have names: {typeless}");

        // Typed decode against the .did -> real field names.
        let typed = decode_bytes_with_did(did, "stats", &bytes).expect("typed decode");
        assert!(typed.contains("name ="), "typed should have `name`: {typed}");
        assert!(typed.contains("url ="), "typed should have `url`: {typed}");
    }
}
