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
mod proposals;

use candid::{types::value::IDLArgs, Principal};
use ic_agent::Agent;
use proposals::Proposals;
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
}

fn default_args() -> String {
    "()".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct ProposeCallArgs {
    /// Target canister principal.
    canister_id: String,
    /// Method name to invoke.
    method: String,
    /// Arguments in textual Candid syntax (same format as `call_canister`).
    #[serde(default = "default_args")]
    args: String,
    /// If true the user will perform a read-only `query`; otherwise an `update`.
    #[serde(default)]
    is_query: bool,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct CheckProposalArgs {
    /// The proposal id returned by `propose_call`.
    proposal_id: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct DiscoverCanistersArgs {
    /// A web domain or URL served from the IC, e.g. "oisy.com".
    domain: String,
}

#[derive(Clone)]
struct IcTools {
    agent: Agent,
    proposals: Proposals,
    tool_router: ToolRouter<IcTools>,
}

#[tool_router]
impl IcTools {
    fn new(agent: Agent, proposals: Proposals) -> Self {
        Self {
            agent,
            proposals,
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
        description = "Call a method on an Internet Computer canister. Arguments are given in textual Candid syntax and the reply is returned as textual Candid. Set is_query=true for read-only query calls."
    )]
    async fn call_canister(
        &self,
        Parameters(CallCanisterArgs {
            canister_id,
            method,
            args,
            is_query,
        }): Parameters<CallCanisterArgs>,
    ) -> Result<CallToolResult, McpError> {
        let principal = match Principal::from_text(&canister_id) {
            Ok(p) => p,
            Err(e) => return Ok(err(format!("invalid canister id: {e}"))),
        };

        // Textual Candid -> binary args.
        let arg_bytes = match candid_parser::parse_idl_args(&args) {
            Ok(parsed) => match parsed.to_bytes() {
                Ok(b) => b,
                Err(e) => return Ok(err(format!("could not encode args `{args}`: {e}"))),
            },
            Err(e) => return Ok(err(format!("could not parse args `{args}`: {e}"))),
        };

        // Call (anonymous).
        let reply = if is_query {
            self.agent
                .query(&principal, &method)
                .with_arg(arg_bytes)
                .call()
                .await
        } else {
            self.agent
                .update(&principal, &method)
                .with_arg(arg_bytes)
                .call_and_wait()
                .await
        };

        let reply_bytes = match reply {
            Ok(b) => b,
            Err(e) => return Ok(err(format!("call failed: {e}"))),
        };

        // Decode the reply using the canister's Candid interface so record/variant
        // field names are recovered (the wire format only carries field-name
        // hashes; type-less decoding would show e.g. `25_979` instead of `name`).
        Ok(ok(self.decode_reply(principal, &method, &reply_bytes).await))
    }

    #[tool(
        description = "Propose ANY canister call (any canister, any method, textual Candid args — same as call_canister) for the user to review and SIGN with their Internet Identity. This does NOT execute the call; it queues a candidate the user must approve and sign on the signing page. The server does not sign. Returns a proposal id and review URL; poll `check_proposal` for the outcome."
    )]
    async fn propose_call(
        &self,
        Parameters(ProposeCallArgs {
            canister_id,
            method,
            args,
            is_query,
        }): Parameters<ProposeCallArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let principal = match Principal::from_text(&canister_id) {
            Ok(p) => p,
            Err(e) => return Ok(err(format!("invalid canister id: {e}"))),
        };
        // Validate the textual Candid parses, so malformed args fail at proposal
        // time. The actual encoding happens in the browser (what-you-see-is-
        // what-you-sign) — the server never produces the bytes that get signed.
        if let Err(e) = candid_parser::parse_idl_args(&args) {
            return Ok(err(format!("could not parse args `{args}`: {e}")));
        }

        // Best-effort fetch of the canister's interface so the browser can
        // encode/decode this call with field names (recovering hashed fields).
        let did = self
            .agent
            .read_state_canister_metadata(principal, "candid:service")
            .await
            .ok()
            .and_then(|b| String::from_utf8(b).ok());

        let proposer = authed_principal(&ctx).unwrap_or_else(|| "unknown".to_string());
        let p = self
            .proposals
            .create_call(canister_id, method, args, is_query, proposer, did)
            .await;

        let url = format!("{}/app", auth::base_url());
        Ok(ok(format!(
            "Proposed call (NOT executed — awaiting the user's signature).\n\
             proposal_id: {}\n\
             {} {} {}\n\
             Ask the user to review and sign it at: {}\n\
             Then call check_proposal with this proposal_id — it will WAIT for the \
             signature and return the result. If it comes back still pending, call \
             check_proposal again.",
            p.id,
            if p.is_query { "query" } else { "update" },
            p.method,
            p.args,
            url
        )))
    }

    #[tool(
        description = "Check a proposal created with propose_call. Waits up to ~25s for the user to sign and returns the result (textual Candid) as soon as it's available; if it returns while still pending, call it again."
    )]
    async fn check_proposal(
        &self,
        Parameters(CheckProposalArgs { proposal_id }): Parameters<CheckProposalArgs>,
    ) -> Result<CallToolResult, McpError> {
        let waited = self
            .proposals
            .wait_for_result(&proposal_id, std::time::Duration::from_secs(25))
            .await;
        match waited {
            Some(p) => Ok(ok(format!(
                "status: {}\ncall: {} {} {}\nresult: {}",
                p.status,
                if p.is_query { "query" } else { "update" },
                p.method,
                p.args,
                p.result.unwrap_or_else(|| "(none yet)".into())
            ))),
            None => Ok(err(format!("no proposal with id {proposal_id}"))),
        }
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

/// The verified II principal of the calling MCP session, if the request carried
/// a valid bearer token (injected by [`auth::require_token`]).
fn authed_principal(ctx: &RequestContext<RoleServer>) -> Option<String> {
    ctx.extensions
        .get::<axum::http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<auth::AuthedPrincipal>())
        .map(|p| p.0.clone())
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
             backend via env.json/JS bundle). `get_candid` fetches a canister's Candid interface; `call_canister` calls \
             a method anonymously with textual Candid in and out; `propose_call` queues ANY \
             canister call for the user to review and sign with their Internet Identity (the \
             server never signs); `check_proposal` reports the signed call's outcome."
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
<p>Tools: <code>get_candid</code>, <code>call_canister</code> (textual Candid in/out).</p>
<p><a href="/app">Signing frontend</a> — sign in with Internet Identity (id.ai) and sign canister calls.</p>
</body></html>"#;

const APP_HTML: &str = include_str!("../static/app.html");

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

    let proposals = Proposals::default();

    let ct = tokio_util::sync::CancellationToken::new();
    let mcp = {
        let agent = agent.clone();
        let proposals = proposals.clone();
        StreamableHttpService::new(
            move || Ok(IcTools::new(agent.clone(), proposals.clone())),
            LocalSessionManager::default().into(),
            StreamableHttpServerConfig::default()
                .with_cancellation_token(ct.child_token())
                .with_allowed_hosts(allowed_hosts()),
        )
    };

    let store = auth::AuthStore::new();

    // Browser-facing proposal API used by /app (signer reviews & reports outcome).
    let api = axum::Router::new()
        .route("/api/proposals", axum::routing::get(proposals::list_pending))
        .route(
            "/api/proposals/{id}/result",
            axum::routing::post(proposals::submit_result),
        )
        .with_state(proposals.clone());

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
        .route("/oauth/authorize", axum::routing::get(auth::authorize))
        .route("/oauth/nonce", axum::routing::get(auth::nonce))
        .route("/oauth/approve", axum::routing::post(auth::approve))
        .route("/oauth/token", axum::routing::post(auth::token))
        .route("/oauth/register", axum::routing::post(auth::register))
        .layer(cors)
        .with_state(store.clone());

    let app = axum::Router::new()
        .route("/", axum::routing::get(|| async { axum::response::Html(INDEX_HTML) }))
        .route("/app", axum::routing::get(|| async { axum::response::Html(APP_HTML) }))
        // Browser-side Candid codec (Rust compiled to WASM) served for /app.
        .nest_service("/wasm", tower_http::services::ServeDir::new("static/wasm"))
        .merge(api)
        .merge(oauth)
        .merge(protected_mcp);

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
