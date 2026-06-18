# mcp-poc

Minimal MCP server that bridges an LLM to the Internet Computer.

The LLM only ever speaks **textual Candid**; this server does all the
encoding/decoding (and, later, signing) against the IC via
[`ic-agent`](https://github.com/dfinity/agent-rs). The MCP layer is the
[official Rust SDK](https://github.com/modelcontextprotocol/rust-sdk) (`rmcp`).

## Tools

| Tool | Args | Returns |
|------|------|---------|
| `discover_canisters` | `domain` | Canister ids behind a web domain (frontend via `x-ic-canister-id`; backend via `/env.json` + JS-bundle mining), each with provenance and its IC dashboard label/type where known |
| `find_canister` | `query` | Canister ids matching a name/symbol, searched in the IC dashboard's service registries — ICRC token ledgers (e.g. `ckUSDC`) and the SNS project catalog |
| `lookup_canister` | `canister_id` | What a canister IS, per the IC dashboard: label/name, type, controllers, subnet, module hash, latest upgrade proposal |
| `get_candid` | `canister_id` | The canister's `candid:service` interface (`.did` text) |
| `call_canister` | `canister_id`, `method`, `args` (textual Candid), `is_query`, `identity` | Reply as textual Candid, called as `anonymous` or a signed-in domain |
| `list_identities` | `wait_for?` | `anonymous` + every signed-in domain (principal + validity); waits for a pending sign-in when `wait_for` is set |
| `sign_in` | `domain` | A short URL the user opens to authorize that domain via Internet Identity |
| `sign_out` | `domain?` | Forget a domain's delegation (or all) |

`discover_canisters` is the entry point when the user names a **website** instead
of a canister id: frontend via the `x-ic-canister-id` header (authoritative),
backend candidates mined from `/env.json` + the JS bundle (pick by label, prefer
production/`IC_` ids, confirm with `get_candid`).

When the user names a **token, project, or service** (e.g. `ckUSDC`) rather than a
website or id, `find_canister` resolves it via
[`dashboard.internetcomputer.org`](https://dashboard.internetcomputer.org)'s public
APIs — the ICRC token registry and the SNS catalog — to the matching canister id(s).
`lookup_canister` goes the other way: given a bare id, it returns the dashboard's
label, type, controllers, subnet, and module hash, so a raw principal becomes an
identified service. (`discover_canisters` results are annotated with these labels
inline.) There is no public name-search over arbitrary canisters, so `find_canister`
covers the IC's labelled services, which is where the meaningful ones live.

`call_canister` runs as `identity` — `anonymous` by default, or a domain you've
signed into. `sign_in(domain)` returns a URL the user opens; after they approve
in II, that domain becomes available as an `identity`. All these tools require a
bearer token (see Auth).

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

The server is a single binary plus the `static/` assets. Two requirements when hosting:

- **HTTPS** — the id.ai passkey (WebAuthn) only works in a secure context.
- **`PUBLIC_URL`** — set it to the public https URL; it's used in the OAuth
  discovery documents, the sign-in redirect/callback, and the allowed-Host list.
  (II's `mcp_server_origin` must be configured to this exact origin.)

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

Set the public base URL (used in discovery docs + the sign-in redirect) with
`PUBLIC_URL`; point the II `/mcp` flow at a deployment with `II_MCP_URL`
(defaults to the staging II canister).

## Domain identities (II `/mcp` delegation)

Instead of signing each call in the browser, the MCP server holds a **per-session
Ed25519 key** and obtains a **delegation** from Internet Identity that acts as
the user's *default account for an app* (II PR
[dfinity/internet-identity#4026](https://github.com/dfinity/internet-identity/pull/4026)).
The server then signs calls as that identity with `ic-agent`'s `DelegatedIdentity`.

Flow:
1. `sign_in("oisy.com")` → a short `…/signin/<link>` URL the user opens.
2. `GET /signin/<link>` checks the browser's `mcp_session` cookie matches the
   link's session, sets a `SameSite=None` flow cookie, and redirects to II's
   `/mcp` (`#public_key&callback&state&app&ttl`).
3. II consent → top-level form-POST of the delegation chain to
   `/signin/callback`, which verifies the flow cookie + single-use `state` and
   stores the delegation under that session + domain.
4. `call_canister(identity="oisy.com", …)` now signs as the user's oisy account.

**Binding:** the delegation can only land in the session that requested it
(`state`), and only via the same browser that authenticated that session
(`mcp_session` cookie at `GET /signin`, `SameSite=None` flow cookie on the
callback) — so a shared sign-in link can't be completed for someone else.

## Roadmap

- [x] Candid tools over MCP streamable-HTTP; `discover_canisters`; Candid
      reference resources.
- [x] OpenID/OAuth auth (authorize page logs in via `@dfinity/auth-client`
      against **id.ai**); verified II delegation; PKCE; expiring tokens.
- [x] Per-session **domain identities** via II's `/mcp` delegation flow
      (`sign_in` / `sign_out` / `list_identities`; `call_canister` `identity`).
- [ ] Persist sessions/delegations (currently in-memory, lost on restart).
- [ ] Scoped delegations / per-call confirmation for sensitive methods.
