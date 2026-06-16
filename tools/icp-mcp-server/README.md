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

### CI builds (recommended)

The [`Build and push image`](../../.github/workflows/docker.yml) workflow builds a
`linux/amd64` image and pushes it to GitHub Container Registry on every push.
After a run on the default branch you get:

```
ghcr.io/<owner>/icp-mcp-server:latest
```

GHCR packages are **private** by default. To let mcplambda.io pull it, either make
the package public (GitHub → repo → Packages → the package → *Package settings* →
*Change visibility*), or give mcplambda.io registry pull credentials.

### Local build (optional)

```sh
# Build from the repo root (the Dockerfile lives there).
docker build -t icp-mcp-server .
docker run -i --rm icp-mcp-server   # -i is required for the stdio transport
```

## Deploy to mcplambda.io

In the **Deploy Docker Image** form:

- **Docker Image**: the pushed image reference, e.g. `ghcr.io/<owner>/icp-mcp-server:latest`
- **Transport**: `stdio`
- **Command arguments**: leave empty (the entrypoint runs the server directly)
- **Environment**: optional — set `RUST_LOG` (e.g. `info`) to control log verbosity; logs go to stderr

Then click **Deploy Server**.
