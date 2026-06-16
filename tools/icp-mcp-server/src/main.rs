use anyhow::Result;
use candid::IDLArgs;
use candid_parser::parse_idl_args;
use ic_agent::{export::Principal, Agent};
use rmcp::{
    handler::server::wrapper::Parameters, schemars, tool, tool_router, transport::stdio, ServiceExt,
};
use serde::Deserialize;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct QueryRequest {
    #[schemars(description = "ICP canister ID, e.g., rdmx6-jaaaa-aaaaa-aaadq-cai")]
    canister_id: String,
    #[schemars(description = "Function name to call on the canister, e.g., config")]
    function_name: String,
    #[schemars(description = "Text-encoded Candid arguments, e.g., ()")]
    candid_payload: String,
}

#[derive(Debug, Clone)]
struct IcpQueryServer;

#[tool_router(server_handler)]
impl IcpQueryServer {
    #[tool(description = "Query a function on an ICP canister using anonymous identity")]
    async fn query(
        &self,
        Parameters(QueryRequest {
            canister_id,
            function_name,
            candid_payload,
        }): Parameters<QueryRequest>,
    ) -> Result<String, String> {
        do_query(canister_id, function_name, candid_payload)
            .await
            .map_err(|e| e.to_string())
    }
}

async fn do_query(
    canister_id: String,
    function_name: String,
    candid_payload: String,
) -> Result<String> {
    let principal = Principal::from_text(&canister_id)?;

    let agent = Agent::builder().with_url("https://ic0.app").build()?;

    let args = parse_idl_args(&candid_payload)?;
    let arg_bytes = args.to_bytes()?;

    let response_bytes = agent
        .query(&principal, &function_name)
        .with_arg(arg_bytes)
        .call()
        .await?;

    let result = IDLArgs::from_bytes(&response_bytes)?;
    Ok(result.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Starting ICP MCP server");

    let service = IcpQueryServer.serve(stdio()).await.inspect_err(|e| {
        tracing::error!("serving error: {:?}", e);
    })?;

    service.waiting().await?;
    Ok(())
}
