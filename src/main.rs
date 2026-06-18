//! Minimal MCP PoC: an MCP server exposing tools over streamable HTTP that talk
//! to the Internet Computer via ic-agent.
//!
//!   1. `get_candid`   — fetch a canister's Candid interface (`candid:service` metadata).
//!   2. `discover_canisters` — find the canisters behind a web domain.
//!   3. `call_canister` — call any method with textual Candid in, textual Candid out,
//!      as `anonymous` or as a domain identity derived ON DEMAND.
//!
//! The LLM only ever deals with textual Candid; encoding/decoding happens here.
//! Anonymous calls use the shared anonymous agent. A domain identity is minted
//! on demand from the connection's standing II delegation (see `identities`).

mod auth;
mod delegation;
mod discover;
mod identities;

use candid::{types::value::IDLArgs, Principal};
use ic_agent::{Agent, Identity};
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
    /// Application domain to call as, e.g. "oisy.com" — its account delegation is
    /// derived on demand for this connection. Omit to call anonymously.
    #[serde(default)]
    domain: Option<String>,
    /// Optional Candid service definition (`.did` text) for the canister. Used to
    /// encode the args to the method's declared types and decode the reply, for
    /// when the canister's own `candid:service` metadata can't be read (e.g.
    /// access-restricted) — get it from get_candid, or ask the user for it.
    #[serde(default)]
    candid: Option<String>,
}

fn default_args() -> String {
    "()".to_string()
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct DiscoverCanistersArgs {
    /// A web domain or URL served from the IC, e.g. "oisy.com".
    domain: String,
}

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct GetPrincipalArgs {
    /// The application domain to resolve, e.g. "oisy.com". Returns the principal
    /// you act as at that app — its account delegation is derived on demand (same
    /// as call_canister) and its principal returned.
    domain: String,
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
        description = "Call a method on an Internet Computer canister with textual Candid in and out. Args are encoded against the method's declared Candid types (so plain literals like 42 coerce correctly — no `: type` annotations needed). Omit `domain` to call anonymously, or pass an application domain (e.g. \"oisy.com\") to call as your account at that app — a short-lived account delegation is derived on demand from this connection's standing Internet Identity credential. Set is_query=true for read-only query calls. If get_candid couldn't fetch the interface, pass the `.did` text as `candid` (e.g. ask the user for it) so args/replies are still typed."
    )]
    async fn call_canister(
        &self,
        Parameters(CallCanisterArgs {
            canister_id,
            method,
            args,
            is_query,
            domain,
            candid,
        }): Parameters<CallCanisterArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let principal = match Principal::from_text(&canister_id) {
            Ok(p) => p,
            Err(e) => return Ok(err(format!("invalid canister id: {e}"))),
        };
        // The interface to encode/decode against: the canister's own
        // candid:service if exposed, else the caller-supplied `candid`.
        let did = self.resolve_did(principal, candid.as_deref()).await;
        let arg_bytes = match encode_args(did.as_deref(), &method, &args) {
            Ok(b) => b,
            Err(e) => return Ok(err(e)),
        };

        // Pick the agent: no domain uses the shared anonymous agent; a domain
        // derives a short-lived account delegation for that app on demand and
        // builds an agent backed by it (the server signs as the user's account
        // for that app).
        let reply = match domain {
            None => raw_call(&self.agent, principal, &method, arg_bytes, is_query).await,
            Some(domain) => {
                let session_id = match authed_session(&ctx) {
                    Some(s) => s.session_id,
                    None => return Ok(err("calling as a domain needs an authenticated session".into())),
                };
                let delegated = match self.identities.delegated_identity(&session_id, &domain).await {
                    Ok(d) => d,
                    Err(e) => return Ok(err(e)),
                };
                let agent = match Agent::builder().with_url(IC_URL).with_identity(delegated).build() {
                    Ok(a) => a,
                    Err(e) => return Ok(err(format!("could not build agent: {e}"))),
                };
                raw_call(&agent, principal, &method, arg_bytes, is_query).await
            }
        };

        let reply_bytes = match reply {
            Ok(b) => b,
            Err(e) => return Ok(err(format!("call failed: {e}"))),
        };
        // Decode against the Candid interface so field names are recovered.
        Ok(ok(decode_reply(did.as_deref(), &method, &reply_bytes)))
    }

    #[tool(
        description = "Get the Internet Computer principal you act as at a given application `domain` (e.g. \"oisy.com\"), without making a canister call. The app's account delegation is derived on demand (same as call_canister) from this connection's standing Internet Identity credential, and its principal is returned. Use this when a flow needs the principal itself (e.g. to look up a balance or account) rather than to invoke a method."
    )]
    async fn get_principal(
        &self,
        Parameters(GetPrincipalArgs { domain }): Parameters<GetPrincipalArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let session_id = match authed_session(&ctx) {
            Some(s) => s.session_id,
            None => return Ok(err("getting a domain principal needs an authenticated session".into())),
        };
        let delegated = match self.identities.delegated_identity(&session_id, &domain).await {
            Ok(d) => d,
            Err(e) => return Ok(err(e)),
        };
        match delegated.sender() {
            Ok(p) => Ok(ok(p.to_text())),
            Err(e) => Ok(err(format!("could not derive principal for '{domain}': {e}"))),
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
    /// The interface to encode/decode against: the canister's own
    /// `candid:service` if exposed, else the caller-supplied `candid`.
    async fn resolve_did(&self, canister: Principal, provided: Option<&str>) -> Option<String> {
        if let Some(did) = self.candid_service(canister).await {
            return Some(did);
        }
        provided.map(str::to_string)
    }

    /// The canister's `candid:service` interface (`.did` text), if exposed.
    async fn candid_service(&self, canister: Principal) -> Option<String> {
        let raw = self
            .agent
            .read_state_canister_metadata(canister, "candid:service")
            .await
            .ok()?;
        String::from_utf8(raw).ok()
    }
}

/// Encode textual Candid args to bytes. With `did` (the canister interface),
/// coerce the args to the method's declared parameter types — so plain literals
/// land as the method expects (`42` -> `nat64`, `1` -> `float64`, `opt`/`vec`
/// element types) with no `: type` annotations. Without it (interface
/// unreadable and no `candid` supplied), fall back to type-less inference, where
/// numeric literals default to `int`/`float64` and must be annotated (see the
/// `candid://textual-syntax` resource).
fn encode_args(did: Option<&str>, method: &str, args_text: &str) -> Result<Vec<u8>, String> {
    let parsed = candid_parser::parse_idl_args(args_text)
        .map_err(|e| format!("could not parse args `{args_text}`: {e}"))?;
    if let Some(did) = did {
        if let Ok((env, Some(actor))) = candid_parser::utils::CandidSource::Text(did).load() {
            if let Ok(func) = env.get_method(&actor, method) {
                return parsed
                    .to_bytes_with_types(&env, &func.args)
                    .map_err(|e| format!("args don't match `{method}`'s Candid signature: {e}"));
            }
        }
    }
    parsed
        .to_bytes()
        .map_err(|e| format!("could not encode args `{args_text}`: {e}"))
}

/// Decode reply `bytes` to textual Candid. With `did`, decode against the
/// method's declared return types so record/variant field names are recovered;
/// otherwise (or on any failure) fall back to type-less decoding.
fn decode_reply(did: Option<&str>, method: &str, bytes: &[u8]) -> String {
    if let Some(text) = did.and_then(|d| decode_bytes_with_did(d, method, bytes)) {
        return text;
    }
    match IDLArgs::from_bytes(bytes) {
        Ok(decoded) => decoded.to_string(),
        Err(e) => format!("(call succeeded but reply is not decodable as Candid: {e})"),
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
             `call_canister` calls a method with textual Candid in/out: omit `domain` to call \
             anonymously, or pass an application domain (e.g. domain=\"oisy.com\") to call as your \
             account at that app — a short-lived (<=5 min) account delegation for it is minted ON \
             DEMAND from this connection's standing Internet Identity credential, no extra sign-in. \
             `get_principal` returns the principal you act as at an application `domain` \
             without making a call — use it when a flow just needs the principal (e.g. to look up \
             a balance or account). The standing credential is obtained when you connect \
             (authenticate via Internet Identity) and lasts ~60 minutes; reconnect when it expires."
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
<p>Tools: <code>discover_canisters</code> (domain → canister ids), <code>get_candid</code>, <code>call_canister</code> (anonymously, or as your account at an application domain, derived on demand from the connection's standing Internet Identity delegation), <code>get_principal</code> (your principal at an application domain, no call). All speak textual Candid.</p>
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

    let store = auth::AuthStore::new(identities.clone());

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
        .route("/oauth/connect/callback", axum::routing::post(auth::connect_callback))
        .route("/oauth/token", axum::routing::post(auth::token))
        .route("/oauth/register", axum::routing::post(auth::register))
        .layer(cors)
        .with_state(store.clone());

    let app = axum::Router::new()
        .route("/", axum::routing::get(|| async { axum::response::Html(INDEX_HTML) }))
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
