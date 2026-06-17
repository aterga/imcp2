# mcp-poc

Minimal MCP server that bridges an LLM to the Internet Computer.

The LLM only ever speaks **textual Candid**; this server does all the
encoding/decoding (and, later, signing) against the IC via
[`ic-agent`](https://github.com/dfinity/agent-rs). The MCP layer is the
[official Rust SDK](https://github.com/modelcontextprotocol/rust-sdk) (`rmcp`).

## Tools

| Tool | Args | Returns |
|------|------|---------|
| `discover_canisters` | `domain` | Canister ids behind a web domain (frontend via `x-ic-canister-id`; backend via `/env.json` + JS-bundle mining), each with provenance |
| `get_candid` | `canister_id` | The canister's `candid:service` interface (`.did` text) |
| `call_canister` | `canister_id`, `method`, `args` (textual Candid), `is_query` | Reply as textual Candid (anonymous call) |
| `propose_call` | `canister_id`, `method`, `args` (textual Candid), `is_query` | A proposal id + `/app` URL for the user to review & **sign** |
| `check_proposal` | `proposal_id` | Status + the signed call's reply as textual Candid |

`discover_canisters` is the entry point when the user names a **website** instead
of a canister id: it returns the frontend canister (the gateway's
`x-ic-canister-id` header — authoritative) plus backend/other candidates mined
from `/env.json` and the JS bundle (labelled where possible). There's no
authoritative reverse lookup for a site's backend, so non-header results are
candidates — pick by label (prefer production/`IC_` ids) and confirm with
`get_candid`.

`call_canister` runs **anonymously**. `propose_call` is how a signed call
happens: the user reviews and signs it on `/app` with their Internet Identity
(see below). `propose_call` / `check_proposal` require a bearer token.

## Connect from an MCP client

Add the server to Claude Code (replace the URL with wherever it's hosted):

```bash
claude mcp add --transport http ic-poc https://YOUR-HOST/mcp
```

Then run `/mcp` → **ic-poc** → authenticate: a browser opens the authorize page,
you sign in with **Internet Identity (id.ai)**, and the four tools become
available. (Any MCP client with remote HTTP + OAuth support works.)

## Run

```bash
cargo run
# serves http://0.0.0.0:8000  (MCP streamable-HTTP at /mcp, info page at /)
# honours $PORT (default 8000) and $PUBLIC_URL (default http://localhost:8000)
```

## Deploy

The server is a single binary plus the `static/` assets (the WASM Candid codec
is prebuilt and committed). Two requirements when hosting:

- **HTTPS** — the id.ai passkey (WebAuthn) only works in a secure context.
- **`PUBLIC_URL`** — set it to the public https URL; it's used in the OAuth
  discovery documents, the `/app` link, and the allowed-Host list.

A `Dockerfile` is included (works on Render / Fly / Cloud Run / Koyeb). For a
zero-signup public URL during testing, expose the local server with a tunnel:

```bash
cargo run &                                   # local server on :8000
cloudflared tunnel --url http://localhost:8000   # prints https://<name>.trycloudflare.com
# restart the server with PUBLIC_URL set to that URL:
PUBLIC_URL=https://<name>.trycloudflare.com cargo run
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

**The principal is verified, not asserted.** After id.ai login the browser signs
a server-issued nonce (`GET /oauth/nonce`) with its delegation identity and
sends the delegation chain. The server (`src/delegation.rs`) verifies:

1. the chain links the session key to the II root (the II canister signature is
   checked against the IC mainnet root key via `ic-signature-verification`);
2. the leaf session key's signature over the nonce (Ed25519 or P-256);
3. the principal is `self_authenticating(root_pubkey)`;
4. no delegation has expired.

Only then is a principal-bound code minted. This matters because the server
keys per-principal session data off that identity — a spoofable principal would
let one user read another's session. (Fund safety is independent: that's
enforced by the IC at signing time, not here.) **PKCE (S256) is enforced**;
codes live 120s, nonces 300s, access tokens 1h.

Set the public base URL (used in discovery docs) with `PUBLIC_URL`
(default `http://localhost:8000`).

## Roadmap

- [x] Two Candid tools over MCP streamable-HTTP, anonymous calls.
- [x] OpenID/OAuth auth between MCP client and server; authorize page logs in
      via `@dfinity/auth-client` against **id.ai** instead of username/password,
      token bound to the II principal.
- [x] Frontend page (`/app`) where the same II identity **signs** canister
      calls client-side; the server never holds the key.
- [x] Verify a signed II **delegation** server-side so the principal is real,
      not browser-asserted (`src/delegation.rs`, unit-tested).
- [x] Enforce PKCE (S256); expire codes / nonces / tokens.
- [x] LLM proposes ANY canister call (`propose_call`); the user reviews &
      **signs it on `/app`** with their II identity. The browser encodes the
      textual Candid locally via Rust-compiled-to-WASM (`candid-wasm/`) and
      decodes the reply locally — what-you-see-is-what-you-sign, with the
      untrusted server never in the encode/decode/sign path.

## Propose → sign → execute loop

`propose_call(canister_id, method, args, is_query)` (authenticated MCP tool)
queues a candidate call bound to the verified principal and returns a proposal
id + the `/app` URL. It does **not** execute anything. On `/app`, after II
login, pending proposals are listed; the user reviews the textual Candid and
clicks sign — the browser:

1. encodes the displayed textual Candid args to bytes locally (WASM);
2. signs & submits the call to the IC with the II identity (`agent.query` /
   `agent.call`);
3. decodes the reply locally (WASM) and posts the textual outcome back.

The LLM reads the result with `check_proposal(proposal_id)`. The server only
brokers the proposal text and records the outcome — it holds no key and never
produces the bytes that get signed.

### Building the WASM codec

```bash
wasm-pack build candid-wasm --target web --release -d ../static/wasm
```

(The built artifacts are committed under `static/wasm/` so the server runs
out of the box.)
