//! Minimal MCP PoC: an MCP server exposing two tools over streamable HTTP that
//! talk to the Internet Computer via ic-agent.
//!
//!   1. `get_candid`   — fetch a canister's Candid interface (`candid:service` metadata).
//!   2. `call_canister` — call any method with textual Candid in, textual Candid out.
//!
//! The LLM only ever deals with textual Candid; encoding/decoding happens here.
//! Calls are anonymous for now (query methods + read-only). Signing comes later.

use candid::{types::value::IDLArgs, Principal};
use ic_agent::Agent;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::*,
    tool, tool_handler, tool_router,
    transport::{
        streamable_http_server::{session::local::LocalSessionManager, tower::StreamableHttpService},
        StreamableHttpServerConfig,
    },
    schemars, ErrorData as McpError, ServerHandler,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const BIND_ADDRESS: &str = "0.0.0.0:8000";
/// Public IC API boundary node. Anonymous queries/updates go here.
const IC_URL: &str = "https://icp-api.io";

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

#[derive(Clone)]
struct IcTools {
    agent: Agent,
    tool_router: ToolRouter<IcTools>,
}

#[tool_router]
impl IcTools {
    fn new(agent: Agent) -> Self {
        Self {
            agent,
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

        // Binary reply -> textual Candid (Candid messages are self-describing).
        match IDLArgs::from_bytes(&reply_bytes) {
            Ok(decoded) => Ok(ok(decoded.to_string())),
            Err(e) => Ok(err(format!(
                "call succeeded but reply could not be decoded as Candid: {e}"
            ))),
        }
    }
}

#[tool_handler]
impl ServerHandler for IcTools {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder().enable_tools().build(),
        )
        .with_server_info(Implementation::from_build_env())
        .with_instructions(
            "Internet Computer tools. `get_candid` fetches a canister's Candid interface; \
             `call_canister` calls a method with textual Candid in and out."
                .to_string(),
        )
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

    let ct = tokio_util::sync::CancellationToken::new();
    let mcp = StreamableHttpService::new(
        move || Ok(IcTools::new(agent.clone())),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_cancellation_token(ct.child_token()),
    );

    let app = axum::Router::new()
        .route("/", axum::routing::get(|| async { axum::response::Html(INDEX_HTML) }))
        .route("/app", axum::routing::get(|| async { axum::response::Html(APP_HTML) }))
        .nest_service("/mcp", mcp);

    let listener = tokio::net::TcpListener::bind(BIND_ADDRESS).await?;
    tracing::info!("listening on http://{BIND_ADDRESS}  (MCP at /mcp)");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            ct.cancel();
        })
        .await?;
    Ok(())
}
