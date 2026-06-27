# mcp-poc

Minimal MCP server that bridges an LLM to the Internet Computer.

The LLM only ever speaks **textual Candid**; this server does all the
encoding/decoding and signing against the IC via
[`ic-agent`](https://github.com/dfinity/agent-rs). The MCP layer is the
[official Rust SDK](https://github.com/modelcontextprotocol/rust-sdk) (`rmcp`).

## Tools

| Tool | Args | Returns |
|------|------|---------|
| `discover_canisters` | `domain` | Canister ids behind a web domain (frontend via `x-ic-canister-id`; backend via `/env.json` + JS-bundle mining), each with provenance and its IC dashboard label/type where known |
| `find_canister` | `query` | Canister ids matching a name/symbol, searched in the IC dashboard's service registries — ICRC token ledgers (e.g. `ckUSDC`) and the SNS project catalog |
| `lookup_canister` | `canister_id` | What a canister IS, per the IC dashboard: label/name, type, controllers, subnet, module hash, latest upgrade proposal |
| `get_candid` | `canister_id` | The canister's `candid:service` interface (`.did` text) |
| `call_canister` | `canister_id`, `method`, `args` (textual Candid), `is_query`, `domain?` | Reply as textual Candid; called anonymously (no `domain`) or as your account at an application domain, derived on demand |
| `get_principal` | `domain` | The principal you act as at an application domain (derives the delegation on demand, same as `call_canister`), without making a call |
| `list_ic_skills` | — | The official [IC skills](https://skills.internetcomputer.org) (Motoko, mops/icp CLIs, cycles, stable memory, security, …), grouped by category |
| `get_ic_skill` | `name` | The full `SKILL.md` instructions for one skill (e.g. `motoko`, `icp-cli`, `cycles-management`) |
| `cycles_balance` | — | Your cycles-ledger balance (the funds `create_canister`/`top_up_canister` spend), as your standing II principal |
| `create_canister` | `cycles?` / `icp?`, `controllers?`, `subnet?` | Create + fund a new canister from your cycles-ledger balance; returns the new canister id |
| `install_code` | `canister_id`, `wasm_base64` / `wasm_hex`, `mode?`, `arg?` | Install/reinstall/upgrade a Wasm module (single-shot, or via the chunk store for large modules) |
| `canister_status` | `canister_id` | Run state, cycle balance, module hash, memory, controllers, allocations |
| `update_canister_settings` | `canister_id`, `controllers?`, allocations, `freezing_threshold?`, `log_visibility?`, … | Update a canister's settings |
| `start_canister` / `stop_canister` / `uninstall_code` / `delete_canister` | `canister_id` | Canister lifecycle |
| `top_up_canister` | `canister_id`, `cycles?` / `icp?` | Add cycles to an existing canister from your cycles-ledger balance |

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

`call_canister` runs anonymously by default; pass a `domain` (e.g. `oisy.com`) to
call as your account at that app. For a domain, the server mints a **short-lived
(≤5 min) account delegation on demand** from the connection's standing Internet
Identity credential (see [Domain identities](#domain-identities-on-demand)) —
there is no per-app sign-in step. `get_principal` returns that account's principal
without a call. All these tools require a bearer token (see Auth).

### Skills awareness

`list_ic_skills` / `get_ic_skill` expose the official Internet Computer
[skills](https://skills.internetcomputer.org) — authoritative, current how-to
guides for authoring and shipping IC apps (the Motoko language, the `mops` and
`icp` CLIs, cycles management, stable memory & upgrades, canister security, DeFi,
auth, …). The catalogue is fetched live from the registry's manifest
(`/api/skills.json`, cached ~15 min) and each skill's `SKILL.md` on demand;
nothing is bundled, so the agent always sees the current skills. They are also
listed as MCP **resources** (`skill://<name>`) alongside the `candid://`
references. Override the registry origin with `SKILLS_URL`.

### Creating & managing canisters

The management tools let the agent act **on chain as your standing Internet
Identity principal** — a stable per-connection identity (the one returned when you
authenticate). Because a user ingress message cannot attach cycles, creation and
top-ups draw from your **cycles-ledger** balance (`um5iw-rqaaa-aaaaq-qaaba-cai`):
fund that principal first (e.g. via the `icp` CLI / `cycles-management` skill),
check it with `cycles_balance`, then `create_canister` (amount in `cycles`, or in
`icp` converted at the CMC's current rate). Lifecycle calls
(`install_code`, `canister_status`, `update_canister_settings`,
`start`/`stop`/`uninstall`/`delete`) go to the management canister (`aaaaa-aa`)
with the effective canister id set to the target. `install_code` takes the
compiled Wasm as base64/hex and uploads it via the chunk store automatically when
it exceeds the single-message limit.

Together these make the end-to-end flow work: *"create a Motoko canister that does
X and deploy a new canister with Y ICP worth of cycles"* → the agent reads the
relevant skills, writes and **builds** the Wasm in its own environment, then
`create_canister(icp = Y)` and `install_code`. (Compiling Motoko/Rust to Wasm
happens in the agent's environment, not in this server.)

## Connect from an MCP client

Add the server to Claude Code (replace the URL with wherever it's hosted):

```bash
claude mcp add --transport http ic-poc https://YOUR-HOST/mcp
```

Then run `/mcp` → **ic-poc** → authenticate: the browser is sent to **Internet
Identity**'s `/mcp` flow, you sign in once, and the tools become available
— that single login is the connection's standing credential. (Any MCP client
with remote HTTP + OAuth support works.)

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
  (II derives the MCP server origin from the connect callback, and each user
  must add this exact origin as their trusted MCP server in II Settings — there
  is no longer a deploy-time `mcp_server_origin` on II's side.)

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
OAuth 2.1 authorization-code flow, except logging in runs **Internet Identity's
`/mcp` delegation flow** instead of username/password, and the issued token is
bound to the resulting **principal**.

Endpoints:

- `GET /.well-known/oauth-authorization-server` — AS metadata
- `GET /.well-known/oauth-protected-resource` — points clients at the AS
- `POST /oauth/register` — dynamic client registration (RFC 7591); the client's
  `redirect_uris` are stored (persisted to `OAUTH_CLIENTS_FILE`) and bound to the
  issued `client_id`
- `GET  /oauth/authorize` — mints the connection's backend key and redirects the
  browser to II's `/mcp` flow, sending the backend **public** key
- `POST /oauth/connect/callback` — II form-POSTs the delegation chain here; the
  server verifies + stores it and redirects back with a principal-bound code
- `POST /oauth/token` — exchanges the code for an access token

Unauthenticated `/mcp` requests get `401` with a `WWW-Authenticate` header
pointing at the resource metadata, as the MCP spec expects.

**Redirect validation is per-client, not a host allowlist.** `/oauth/authorize`
accepts a `redirect_uri` only if the requesting `client_id` registered it (exact
match, OAuth 2.1) — so any registration-compliant client (Claude, ChatGPT, Grok,
…) works without code changes, and the server can't be steered to an
unregistered URL. The one exception is loopback (`http://127.0.0.1|localhost|[::1]`,
any port) per RFC 8252, for native clients that bind an ephemeral callback port.

**No private key is ever transmitted.** The backend generates a per-connection
Ed25519 key and sends only its **public** key to II. II logs the user in and
returns a delegation chain `anchor → backend key` (the 60-minute standing
credential). The chain itself is the proof of identity, so there is no nonce
round-trip; the server (`src/delegation.rs`) verifies:

1. the chain links to the II root (the II canister signature is checked against
   the IC mainnet root key via `ic-signature-verification`);
2. no delegation has expired;
3. the chain ends at this connection's backend key (so the backend, holding the
   private half, can sign with it);
4. the principal is `self_authenticating(user_key)`.

Only then is a principal-bound code minted. This matters because the server
keys per-principal session data off that identity — a spoofable principal would
let one user read another's session. (Fund safety is independent: that's
enforced by the IC at signing time, not here.) **PKCE (S256) is enforced**;
codes live 120s, connects 600s, access tokens 1h.

Set the public base URL (used in the discovery docs and as the MCP origin) with
`PUBLIC_URL`. The Internet Identity instance is `II_URL` (browser login, default
`beta.id.ai`) plus `II_CANISTER_ID` (the canister the account-delegation calls
target, default `fgte5-ciaaa-aaaad-aaatq-cai`) — both point at the same II.

## Domain identities (on demand)

There is no per-app browser sign-in. Instead the model is:

- **One standing credential per connection.** When you connect (authenticate via
  Internet Identity), the backend obtains a **60-minute standing delegation** —
  a chain `anchor → backend session key` issued for the MCP origin. The backend
  holds a per-session Ed25519 key that this delegation ends at, so it can sign as
  the anchor's MCP-origin principal. Reconnect when it expires.
- **App delegations minted on demand.** When `call_canister` (or `get_principal`)
  is invoked with a `domain` (e.g. `oisy.com`), the backend mints a **short-lived
  (≤5 min) per-app account delegation on demand**: signing *as the standing
  identity*, it calls Internet Identity's account-derivation methods directly —
  no browser round-trip — with the app's target origin and the backend session
  key as `session_key`. The returned chain ends at the backend session key, so
  the backend signs the canister call with `ic-agent`'s `DelegatedIdentity`.

The on-demand derivation calls two **new II canister methods**:

```candid
mcp_prepare_account_delegation :
  (target_origin: text, account_number: opt nat64, session_key: blob, max_ttl: opt nat64)
    -> (variant {
         Ok: record { user_key: blob; account_number: opt nat64; expiration: nat64 };
         Err: AccountDelegationError });
mcp_get_account_delegation :
  (target_origin: text, account_number: opt nat64, session_key: blob, expiration: nat64)
    -> (variant { Ok: SignedDelegation; Err: AccountDelegationError }) query;
```

- `target_origin` is `https://<domain>`, with IC gateway domains remapped:
  `*.icp0.io` / `*.icp.net` → `*.ic0.app`.
- `account_number` names which of the anchor's accounts at `target_origin` to act
  as; `null` selects the (mutable) default account there. `prepare` resolves it
  and returns the concrete account in its reply, which is threaded back into
  `get` so both calls sign for the same account. The server passes `null`.
- These methods live on the **same II instance** as the connect-time login:
  `II_URL` (default `https://beta.id.ai`) is the browser login origin and
  `II_CANISTER_ID` (default `fgte5-ciaaa-aaaad-aaatq-cai`, that instance's
  canister) is the canister these calls target, over `https://icp-api.io`.
- Derived delegations are cached per `(session, domain)` and reused until they
  near expiry, then re-derived.

> **Status:** the standing-credential connect flow runs against II's existing
> `/mcp` delegation flow. The two `mcp_*_account_delegation` canister methods used
> for on-demand app delegations were introduced in
> [dfinity/internet-identity#4034](https://github.com/dfinity/internet-identity/pull/4034)
> and reshaped (account-bound delegations) in
> [dfinity/internet-identity#4052](https://github.com/dfinity/internet-identity/pull/4052);
> the on-demand path works once that II build is deployed to the configured
> `II_URL` (the server is built against the same candid contract).

## Roadmap

- [x] Candid tools over MCP streamable-HTTP; `discover_canisters`; Candid
      reference resources.
- [x] OpenID/OAuth auth: connecting runs II's `/mcp` delegation flow (backend
      public key out, delegation in); verified II delegation; PKCE; expiring tokens.
- [x] On-demand **domain identities**: a 60-min standing II delegation per
      connection mints ≤5-min per-app account delegations directly via II canister
      methods (`call_canister`/`get_principal` `domain`); no per-app browser flow.
- [ ] Deploy the `mcp_*_account_delegation` canister methods (server is built
      against their candid contract; the live round-trip lands with the II side).
- [ ] Persist sessions/delegations (currently in-memory, lost on restart).
- [ ] Scoped delegations / per-call confirmation for sensitive methods.
