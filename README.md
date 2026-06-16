# mcp-poc

Minimal MCP server that bridges an LLM to the Internet Computer.

The LLM only ever speaks **textual Candid**; this server does all the
encoding/decoding (and, later, signing) against the IC via
[`ic-agent`](https://github.com/dfinity/agent-rs). The MCP layer is the
[official Rust SDK](https://github.com/modelcontextprotocol/rust-sdk) (`rmcp`).

## Tools

| Tool | Args | Returns |
|------|------|---------|
| `get_candid` | `canister_id` | The canister's `candid:service` interface (`.did` text) |
| `call_canister` | `canister_id`, `method`, `args` (textual Candid), `is_query` | Reply as textual Candid |

Calls are currently **anonymous** — query methods and read-only update calls.
Authenticated/signed calls are the next milestone.

## Run

```bash
cargo run
# serves http://0.0.0.0:8000  (MCP streamable-HTTP at /mcp, info page at /)
```

## Try it (raw MCP over curl)

```bash
# 1. initialize, grab the session id
SID=$(curl -s -D - -o /dev/null \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}' \
  http://127.0.0.1:8000/mcp | grep -i '^mcp-session-id' | tr -d '\r' | awk '{print $2}')

H=(-H "Accept: application/json, text/event-stream" -H "Content-Type: application/json" -H "Mcp-Session-Id: $SID")
curl -s "${H[@]}" -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' http://127.0.0.1:8000/mcp >/dev/null

# 2. call a real mainnet canister (ICP ledger)
curl -s "${H[@]}" -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"call_canister","arguments":{"canister_id":"ryjl3-tyaaa-aaaaa-aaaba-cai","method":"icrc1_name","args":"()","is_query":true}}}' \
  http://127.0.0.1:8000/mcp | grep '^data: {' | sed 's/^data: //' | jq -r '.result.content[0].text'
# => ("Internet Computer")
```

## Auth (OAuth 2.1, login via Internet Identity)

`/mcp` is gated by a bearer token. The MCP client obtains it with a standard
OAuth 2.1 authorization-code flow — except the authorize page logs the user in
with **Internet Identity (id.ai)** via `@dfinity/auth-client` instead of
username/password, and the issued token is bound to the resulting **principal**.

Endpoints:

- `GET /.well-known/oauth-authorization-server` — AS metadata
- `GET /.well-known/oauth-protected-resource` — points clients at the AS
- `POST /oauth/register` — dynamic client registration
- `GET  /oauth/authorize` — serves the id.ai login page
- `POST /oauth/approve` — called after II login; mints a principal-bound code
- `POST /oauth/token` — exchanges the code for an access token

Unauthenticated `/mcp` requests get `401` with a `WWW-Authenticate` header
pointing at the resource metadata, as the MCP spec expects.

Set the public base URL (used in discovery docs) with `PUBLIC_URL`
(default `http://localhost:8000`).

## Roadmap

- [x] Two Candid tools over MCP streamable-HTTP, anonymous calls.
- [x] OpenID/OAuth auth between MCP client and server; authorize page logs in
      via `@dfinity/auth-client` against **id.ai** instead of username/password,
      token bound to the II principal.
- [x] Frontend page (`/app`) where the same II identity **signs** canister
      calls client-side; the server never holds the key.
- [ ] Verify a signed II **delegation** at `/oauth/approve` instead of trusting
      the browser-asserted principal (see `auth.rs` TODO).
- [ ] Enforce PKCE; expire tokens/sessions.
- [ ] Have the LLM propose a candidate canister call that the user reviews &
      signs on `/app` (what-you-see-is-what-you-sign), with the server relaying
      the signed ingress envelope.
