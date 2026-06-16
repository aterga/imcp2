# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM rust:1-bookworm AS builder

WORKDIR /build

# Copy the whole workspace so the workspace Cargo.toml resolves the member.
COPY Cargo.toml ./
COPY tools/icp-mcp-server ./tools/icp-mcp-server

RUN cargo build --release -p icp-mcp-server

# ---- Runtime stage ----
FROM debian:bookworm-slim

# ic-agent talks to IC mainnet over HTTPS, so TLS roots are required.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/icp-mcp-server /usr/local/bin/icp-mcp-server

# The server speaks MCP over stdio.
ENTRYPOINT ["/usr/local/bin/icp-mcp-server"]
