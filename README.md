# mcp-poc

Minimal MCP server that bridges an LLM to the Internet Computer.

The LLM only ever speaks **textual Candid**; this server does all the
encoding/decoding and signing against the IC via
[`ic-agent`](https://github.com/dfinity/agent-rs). The MCP layer is the
[official Rust SDK](https://github.com/modelcontextprotocol/rust-sdk) (`rmcp`).

## Tools

| Tool | Args | Returns |
|------|------|---------|
| `discover_canisters` | `domain` | Canister ids behind a web domain (frontend via `x-ic-canister-id`; backend via `/env.json` + JS-bundle mining), each with provenance |
| `get_candid` | `canister_id` | The canister's `candid:service` interface (`.did` text) |
| `call_canister` | `canister_id`, `method`, `args` (textual Candid), `is_query`, `identity` | Reply as textual Candid, called as `anonymous` or as a domain identity derived on demand |

`discover_canisters` is the entry point when the user names a **website** instead
of a canister id: frontend via the `x-ic-canister-id` header (authoritative),
backend candidates mined from `/env.json` + the JS bundle (pick by label, prefer
production/`IC_` ids, confirm with `get_candid`).

`call_canister` runs as `identity` — `anonymous` by default, or a domain (e.g.
`oisy.com`). For a domain, the server mints a **short-lived (≤5 min) account
delegation for that app on demand** from the connection's standing Internet
Identity credential (see [Domain identities](#domain-identities-on-demand)) —
there is no per-app sign-in step. All these tools require a bearer token
(see Auth).

## Connect from an MCP client

Add the server to Claude Code (replace the URL with wherever it's hosted):

```bash
claude mcp add --transport http ic-poc https://YOUR-HOST/mcp
```

Then run `/mcp` → **ic-poc** → authenticate: a browser opens the authorize page,
you sign in with **Internet Identity (id.ai)**, and the three tools become
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

Set the public base URL (used in the discovery docs) with `PUBLIC_URL`; point
the connector login at an II instance with `II_URL` (defaults to `beta.id.ai`).

## Domain identities (on demand)

There is no per-app browser sign-in. Instead the model is:

- **One standing credential per connection.** When you connect (authenticate via
  Internet Identity), the backend obtains a **60-minute standing delegation** —
  a chain `anchor → backend session key` issued for the MCP origin. The backend
  holds a per-session Ed25519 key that this delegation ends at, so it can sign as
  the anchor's MCP-origin principal. Reconnect when it expires.
- **App delegations minted on demand.** When `call_canister` is invoked with a
  domain `identity` (e.g. `oisy.com`), the backend mints a **short-lived
  (≤5 min) per-app account delegation on demand**: signing *as the standing
  identity*, it calls Internet Identity's account-derivation methods directly —
  no browser round-trip — with the app's target origin and the backend session
  key as `session_key`. The returned chain ends at the backend session key, so
  the backend signs the canister call with `ic-agent`'s `DelegatedIdentity`.

The on-demand derivation calls two **new II canister methods**:

```candid
mcp_prepare_account_delegation :
  (target_origin: text, session_key: blob, max_ttl_ns: opt nat64)
    -> (record { user_key: blob; expiration: nat64 });
mcp_get_account_delegation :
  (target_origin: text, session_key: blob, expiration: nat64)
    -> (variant { Ok: SignedDelegation; Err: text });
```

- `target_origin` is `https://<domain>`, with IC gateway domains remapped:
  `*.icp0.io` / `*.icp.net` → `*.ic0.app`.
- The II canister is configured with `II_CANISTER_ID` (defaults to the II
  staging-B frontend canister `uhh2r-oyaaa-aaaad-agbva-cai`), called over
  `https://icp-api.io`.
- Derived delegations are cached per `(session, domain)` and reused until they
  near expiry, then re-derived.

> **Status:** the II canister methods above are **not deployed yet**, and the
> connect-time flow that mints the 60-minute standing credential is **not landed
> yet**. The acquisition of the standing credential is stubbed behind a single
> clearly-`TODO`'d function (`Identities::standing_identity`) that returns an
> explanatory error; once the II side lands it returns the real
> `DelegatedIdentity`. Everything compiles; the live II round-trip can't be
> exercised until then.

## Roadmap

- [x] Candid tools over MCP streamable-HTTP; `discover_canisters`; Candid
      reference resources.
- [x] OpenID/OAuth auth (authorize page logs in via `@dfinity/auth-client`
      against **id.ai**); verified II delegation; PKCE; expiring tokens.
- [x] On-demand **domain identities**: a 60-min standing II delegation per
      connection mints ≤5-min per-app account delegations directly via II canister
      methods (`call_canister` `identity`); no per-app browser flow.
- [ ] Land the II connect-time standing-credential flow + deploy the
      `mcp_*_account_delegation` canister methods (currently stubbed/contract-only).
- [ ] Persist sessions/delegations (currently in-memory, lost on restart).
- [ ] Scoped delegations / per-call confirmation for sensitive methods.
