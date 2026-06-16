# icp-mcp-server

An MCP server (built on the Rust [`rmcp`](https://crates.io/crates/rmcp) SDK) that
exposes a single `query` tool for making anonymous query calls to ICP canisters on
IC mainnet. It communicates over **stdio**.

## Tool

`query` — arguments:

| Field            | Description                                           |
| ---------------- | ----------------------------------------------------- |
| `canister_id`    | Canister ID, e.g. `rdmx6-jaaaa-aaaaa-aaadq-cai`       |
| `function_name`  | Query method to call, e.g. `config`                   |
| `candid_payload` | Text-encoded Candid arguments, e.g. `()`              |

## Run locally

```sh
cargo run -p icp-mcp-server
```

## Docker

The image runs the server over stdio (its entrypoint is the binary).

```sh
# Build from the repo root (the Dockerfile lives there).
docker build -t ghcr.io/<owner>/icp-mcp-server:latest .

# Push to a registry your deployment target can pull from.
docker push ghcr.io/<owner>/icp-mcp-server:latest
```

## Deploy to mcplambda.io

In the **Deploy Docker Image** form:

- **Docker Image**: the pushed image reference, e.g. `ghcr.io/<owner>/icp-mcp-server:latest`
- **Transport**: `stdio`
- **Command arguments**: leave empty (the entrypoint runs the server directly)
- **Environment**: optional — set `RUST_LOG` (e.g. `info`) to control log verbosity; logs go to stderr

Then click **Deploy Server**.
