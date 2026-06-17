//! Per-session delegated identities, obtained via Internet Identity's `/mcp`
//! flow (II PR dfinity/internet-identity#4026).
//!
//! Model: the MCP server holds an Ed25519 **session key per authenticated MCP
//! (OpenID) session**. To "sign in to a domain" the user is sent a short URL;
//! it redirects their browser to II's `/mcp` with our session public key, II
//! consent happens, and II form-POSTs a delegation chain back to our callback —
//! a chain that ends at our session key and acts as the user's *default account
//! for that app*. We then sign canister calls as that identity with `ic-agent`.
//!
//! Binding (so a delegation can only land in the session that requested it, and
//! only with the user's explicit, informed consent):
//!   * `link`  — unguessable, single-use, in the short URL, bound to the
//!     requesting session. Any browser may open it: connector clients (ChatGPT,
//!     Claude) run OAuth in an isolated/ephemeral browser, so we cannot require a
//!     shared `mcp_session` cookie when the user later opens the link elsewhere.
//!   * a `SameSite=None` flow cookie set at `GET /signin/<link>` is required on
//!     both the cross-site callback POST and the confirm POST (keeps the II
//!     round-trip in one browser).
//!   * `state` — single-use, routes the callback to the requesting session.
//!   * a post-login **confirmation page** shows the *verified* principal + target
//!     domain before the delegation is stored. A victim phished into opening
//!     someone else's link must knowingly approve connecting their identity to
//!     the requesting assistant session — replacing the old cookie binding.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use candid::Principal;
use ic_agent::{
    identity::{BasicIdentity, DelegatedIdentity, Delegation, SignedDelegation},
    Identity,
};
use serde::Deserialize;
use tokio::sync::RwLock;

/// Single Internet Identity instance used by BOTH the connector sign-in
/// (`authorize.html`) and the app delegation flow. Override with `II_URL`.
/// TODO: switch this default to the II staging-B origin once confirmed; the
/// value below is the previously-used app-delegation II instance so the unified
/// flow keeps working in the meantime.
const II_URL_DEFAULT: &str = "https://uhh2r-oyaaa-aaaad-agbva-cai.icp0.io";
const DEFAULT_TTL_MINUTES: u64 = 60;

/// Origin of the II instance (no trailing path), e.g. `https://<canister>.icp0.io`.
pub fn ii_url() -> String {
    std::env::var("II_URL").unwrap_or_else(|_| II_URL_DEFAULT.to_string())
}

/// II `/mcp` delegation endpoint, derived from [`ii_url`] so the connector login
/// and the app delegation always target the same instance. `II_MCP_URL` still
/// overrides it directly if needed.
fn ii_mcp_url() -> String {
    std::env::var("II_MCP_URL")
        .unwrap_or_else(|_| format!("{}/mcp", ii_url().trim_end_matches('/')))
}

/// Where to send the browser after the callback so II's `/mcp` page shows the
/// outcome (it owns the success/error UI).
pub fn ii_status_url(success: bool) -> String {
    // II reads `status` from the URL fragment, like the request params.
    format!("{}#status={}", ii_mcp_url(), if success { "success" } else { "error" })
}
fn public_url() -> String {
    std::env::var("PUBLIC_URL").unwrap_or_else(|_| "http://localhost:8000".to_string())
}
fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
}
fn random_token() -> String {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).expect("getrandom");
    hex::encode(b)
}

struct Session {
    /// Ed25519 session-key seed; rebuild a `BasicIdentity` from it on demand.
    key_seed: [u8; 32],
    /// DER public key of the session key (sent to II as `publicKey`).
    pubkey_der: Vec<u8>,
    /// domain -> delegation acting as the user's account for that app.
    delegations: HashMap<String, Stored>,
}

struct Stored {
    user_key: Vec<u8>,
    chain: Vec<SignedDelegation>,
    expiration_ns: u64,
    principal: String,
}

struct Link {
    session_id: String,
    domain: String,
}

struct PendingState {
    session_id: String,
    domain: String,
    flow: String,
}

/// A verified delegation awaiting the user's explicit confirmation before it is
/// stored into the requesting session (see the confirmation page).
struct PendingDelegation {
    session_id: String,
    domain: String,
    /// Flow cookie that must accompany the confirm POST (same-browser check).
    flow: String,
    user_key: Vec<u8>,
    chain: Vec<SignedDelegation>,
    expiration_ns: u64,
    principal: String,
}

#[derive(Clone, Default)]
pub struct Identities {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    links: Arc<RwLock<HashMap<String, Link>>>,
    states: Arc<RwLock<HashMap<String, PendingState>>>,
    pending: Arc<RwLock<HashMap<String, PendingDelegation>>>,
}

/// One row of `list_identities`.
pub struct IdentityInfo {
    pub name: String,
    pub principal: String,
    pub note: String,
}

impl Identities {
    pub fn new() -> Self {
        Self::default()
    }

    async fn ensure_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.entry(session_id.to_string()).or_insert_with(|| {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).expect("getrandom");
            let pubkey_der = BasicIdentity::from_raw_key(&seed)
                .public_key()
                .expect("ed25519 public key");
            Session {
                key_seed: seed,
                pubkey_der,
                delegations: HashMap::new(),
            }
        });
    }

    /// Tool step: queue a sign-in and return the short URL the user must visit.
    pub async fn start_sign_in(&self, session_id: &str, domain: &str) -> String {
        self.ensure_session(session_id).await;
        let link = random_token();
        self.links.write().await.insert(
            link.clone(),
            Link {
                session_id: session_id.to_string(),
                domain: domain.to_string(),
            },
        );
        format!("{}/signin/{}", public_url(), link)
    }

    /// `GET /signin/<link>`: consume the single-use link and produce the II
    /// redirect URL + the flow cookie value to set. Any browser may open the
    /// link; the user explicitly confirms after logging in (see [`Self::finalize`]).
    pub async fn begin_redirect(&self, link: &str) -> Result<(String, String), String> {
        let Link { session_id, domain } = self
            .links
            .write()
            .await
            .remove(link)
            .ok_or("unknown or used sign-in link")?;

        let (pubkey_b64, _) = self.pubkey(&session_id).await.ok_or("no session key")?;
        let state = random_token();
        let flow = random_token();
        self.states.write().await.insert(
            state.clone(),
            PendingState {
                session_id,
                domain: domain.clone(),
                flow: flow.clone(),
            },
        );

        let callback = format!("{}/signin/callback", public_url());
        let url = format!(
            "{ii}#public_key={pk}&callback={cb}&state={st}&app={app}&ttl={ttl}",
            ii = ii_mcp_url(),
            pk = urlencoding::encode(&pubkey_b64),
            cb = urlencoding::encode(&callback),
            st = urlencoding::encode(&state),
            app = urlencoding::encode(&domain),
            ttl = DEFAULT_TTL_MINUTES,
        );
        Ok((url, flow))
    }

    /// `POST /signin/callback`: verify the flow cookie + state, parse the verified
    /// delegation, and stage it pending the user's explicit confirmation. Returns
    /// a single-use confirm token routing the browser to the confirmation page.
    pub async fn complete_callback(
        &self,
        state: &str,
        flow_cookie: Option<&str>,
        delegation_json: &str,
    ) -> Result<String, String> {
        let pending = self
            .states
            .write()
            .await
            .remove(state)
            .ok_or("unknown or used state")?;
        match flow_cookie {
            Some(f) if f == pending.flow => {}
            _ => return Err("flow cookie missing or mismatched".into()),
        }

        let (user_key, chain, expiration_ns) = parse_delegation(delegation_json)?;
        let principal = Principal::self_authenticating(&user_key).to_text();

        let confirm = random_token();
        self.pending.write().await.insert(
            confirm.clone(),
            PendingDelegation {
                session_id: pending.session_id,
                domain: pending.domain,
                flow: pending.flow,
                user_key,
                chain,
                expiration_ns,
                principal,
            },
        );
        Ok(confirm)
    }

    /// The (verified principal, domain) staged under a confirm token, for the
    /// confirmation page. Does not consume the token.
    pub async fn confirm_info(&self, confirm: &str) -> Option<(String, String)> {
        let pending = self.pending.read().await;
        let p = pending.get(confirm)?;
        Some((p.principal.clone(), p.domain.clone()))
    }

    /// `POST /signin/confirm`: the user approved. Verify the flow cookie, then
    /// store the staged delegation under the requesting session/domain.
    pub async fn finalize(&self, confirm: &str, flow_cookie: Option<&str>) -> Result<(), String> {
        let staged = self
            .pending
            .write()
            .await
            .remove(confirm)
            .ok_or("unknown or used confirmation")?;
        match flow_cookie {
            Some(f) if f == staged.flow => {}
            _ => return Err("flow cookie missing or mismatched".into()),
        }

        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(&staged.session_id)
            .ok_or("session vanished")?;
        session.delegations.insert(
            staged.domain,
            Stored {
                user_key: staged.user_key,
                chain: staged.chain,
                expiration_ns: staged.expiration_ns,
                principal: staged.principal,
            },
        );
        Ok(())
    }

    /// Forget a domain's delegation (or all of them). Returns how many were removed.
    pub async fn sign_out(&self, session_id: &str, domain: Option<&str>) -> usize {
        let mut sessions = self.sessions.write().await;
        let Some(s) = sessions.get_mut(session_id) else { return 0 };
        match domain {
            Some(d) => s.delegations.remove(d).is_some() as usize,
            None => {
                let n = s.delegations.len();
                s.delegations.clear();
                n
            }
        }
    }

    async fn pubkey(&self, session_id: &str) -> Option<(String, Vec<u8>)> {
        let sessions = self.sessions.read().await;
        let s = sessions.get(session_id)?;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&s.pubkey_der);
        Some((b64, s.pubkey_der.clone()))
    }

    /// Wait (bounded) until `domain` has a live delegation for the session, so a
    /// caller can sign in and then confirm in one step instead of polling. Returns
    /// true if it landed, false on timeout.
    pub async fn wait_for_delegation(
        &self,
        session_id: &str,
        domain: &str,
        timeout: std::time::Duration,
    ) -> bool {
        let steps = (timeout.as_millis() / 500).max(1);
        for _ in 0..steps {
            {
                let sessions = self.sessions.read().await;
                if let Some(s) = sessions.get(session_id) {
                    if s.delegations.get(domain).is_some_and(|d| d.expiration_ns > now_ns()) {
                        return true;
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        false
    }

    /// `list_identities`: anonymous + every signed-in domain.
    pub async fn list(&self, session_id: &str) -> Vec<IdentityInfo> {
        let mut out = vec![IdentityInfo {
            name: "anonymous".into(),
            principal: Principal::anonymous().to_text(),
            note: "unauthenticated calls".into(),
        }];
        if let Some(s) = self.sessions.read().await.get(session_id) {
            let now = now_ns();
            for (domain, d) in &s.delegations {
                let mins_left = d.expiration_ns.saturating_sub(now) / 60_000_000_000;
                out.push(IdentityInfo {
                    name: domain.clone(),
                    principal: d.principal.clone(),
                    note: if d.expiration_ns <= now {
                        "EXPIRED — sign in again".into()
                    } else {
                        format!("~{mins_left} min left")
                    },
                });
            }
        }
        out
    }

    /// Build the `ic-agent` identity for a domain (None for anonymous handled by caller).
    pub async fn delegated_identity(
        &self,
        session_id: &str,
        domain: &str,
    ) -> Result<DelegatedIdentity, String> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id).ok_or("no such session")?;
        let stored = session
            .delegations
            .get(domain)
            .ok_or_else(|| format!("not signed in to '{domain}' — call sign_in first"))?;
        if stored.expiration_ns <= now_ns() {
            return Err(format!("delegation for '{domain}' expired — call sign_in again"));
        }
        let key = BasicIdentity::from_raw_key(&session.key_seed);
        DelegatedIdentity::new(stored.user_key.clone(), Box::new(key), stored.chain.clone())
            .map_err(|e| format!("invalid delegation chain: {e}"))
    }
}

#[derive(Deserialize)]
struct ChainJson {
    #[serde(rename = "publicKey")]
    public_key: String,
    delegations: Vec<SignedDelJson>,
}
#[derive(Deserialize)]
struct SignedDelJson {
    delegation: DelJson,
    signature: String,
}
#[derive(Deserialize)]
struct DelJson {
    pubkey: String,
    expiration: String,
    #[serde(default)]
    targets: Option<Vec<String>>,
}

/// Parse `DelegationChain.toJSON()` into (user_key DER, chain, max expiration ns).
fn parse_delegation(json: &str) -> Result<(Vec<u8>, Vec<SignedDelegation>, u64), String> {
    let chain: ChainJson = serde_json::from_str(json).map_err(|e| format!("bad delegation JSON: {e}"))?;
    let user_key = hex::decode(&chain.public_key).map_err(|_| "bad publicKey hex")?;
    let mut out = Vec::with_capacity(chain.delegations.len());
    let mut max_exp = 0u64;
    for d in chain.delegations {
        let expiration = u64::from_str_radix(d.delegation.expiration.trim_start_matches("0x"), 16)
            .map_err(|_| "bad expiration")?;
        max_exp = max_exp.max(expiration);
        let targets = match d.delegation.targets {
            Some(ts) => Some(
                ts.iter()
                    .map(|t| hex::decode(t).map(|b| Principal::from_slice(&b)))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| "bad target hex")?,
            ),
            None => None,
        };
        out.push(SignedDelegation {
            delegation: Delegation {
                pubkey: hex::decode(&d.delegation.pubkey).map_err(|_| "bad delegation pubkey hex")?,
                expiration,
                targets,
            },
            signature: hex::decode(&d.signature).map_err(|_| "bad delegation signature hex")?,
        });
    }
    Ok((user_key, out, max_exp))
}
