//! On-demand per-app delegated identities.
//!
//! Model: at connect/OpenID time the MCP backend obtains a **60-minute standing
//! delegation** from Internet Identity — a chain `anchor -> backend session key`
//! issued for the MCP origin. The backend holds an Ed25519 **session key per
//! authenticated MCP (OpenID) session**; the standing delegation ends at that
//! key, so the backend can sign as the anchor's MCP-origin principal.
//!
//! To call a canister as the user's account for a given app (e.g. `oisy.com`)
//! the backend mints a **short-lived (<=5 min) per-app account delegation ON
//! DEMAND**: signing AS the standing identity, it calls II's
//! `mcp_prepare_account_delegation` / `mcp_get_account_delegation` directly with
//! the app's target origin and the backend session key as `session_key`. The
//! returned chain ends at the backend session key, so the backend can sign
//! canister calls as that per-app identity with `ic-agent`'s `DelegatedIdentity`.
//! There is no per-app browser sign-in flow.
//!
//! The derived `(user_key, chain, expiration)` is cached per `(session_id,
//! domain)` with a TTL slightly under the delegation's expiration; it is reused
//! until near-expiry, then re-derived.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::{
    identity::{BasicIdentity, DelegatedIdentity, Delegation, SignedDelegation},
    Agent, Identity,
};
use serde::Deserialize;
use tokio::sync::RwLock;

/// Public IC API boundary node the II canister calls are made against.
const IC_URL: &str = "https://icp-api.io";

/// Default Internet Identity canister: the II staging-B frontend canister.
/// Override with `II_CANISTER_ID`.
const II_CANISTER_ID_DEFAULT: &str = "uhh2r-oyaaa-aaaad-agbva-cai";

/// Requested lifetime of an on-demand app delegation: 5 minutes (the contract's
/// `max_ttl_ns`). The cache TTL is set slightly under the returned expiration.
const APP_DELEGATION_TTL_NS: u64 = 5 * 60 * 1_000_000_000;

/// Re-derive once the cached delegation is within this margin of expiry, so a
/// call never goes out with an about-to-expire delegation.
const REDERIVE_MARGIN_NS: u64 = 30 * 1_000_000_000;

/// Internet Identity instance used by the connector login (`authorize.html`).
/// Override with `II_URL`. Default: **`beta.id.ai`** (II Staging A). A real
/// domain is required: the raw `<canister>.icp0.io` origin is rate-limited
/// (HTTP 429) for the browser login SPA, leaving the II popup blank.
const II_URL_DEFAULT: &str = "https://beta.id.ai";

/// Origin of the II login instance (no trailing slash). This is the instance the
/// connect-time OpenID login (and, once landed, the standing-credential flow)
/// targets — distinct from the canister the on-demand account-delegation methods
/// are called on (`II_CANISTER_ID`).
pub fn ii_url() -> String {
    let raw = std::env::var("II_URL").unwrap_or_else(|_| II_URL_DEFAULT.to_string());
    raw.trim_end_matches('/').to_string()
}

/// The II canister the on-demand delegation methods live on.
fn ii_canister_id() -> Result<Principal, String> {
    let raw = std::env::var("II_CANISTER_ID").unwrap_or_else(|_| II_CANISTER_ID_DEFAULT.to_string());
    Principal::from_text(&raw).map_err(|e| format!("invalid II_CANISTER_ID '{raw}': {e}"))
}

fn now_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
}

/// Remap a domain to the `target_origin` II expects for account derivation.
/// IC gateway domains (`*.icp0.io`, `*.icp.net`) map to the canonical
/// `*.ic0.app` origin; any other domain is passed through as `https://<domain>`.
fn target_origin(domain: &str) -> String {
    let host = domain
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = host.split('/').next().unwrap_or(host);
    for gateway in [".icp0.io", ".icp.net"] {
        if let Some(label) = host.strip_suffix(gateway) {
            return format!("https://{label}.ic0.app");
        }
    }
    format!("https://{host}")
}

struct Session {
    /// Ed25519 session-key seed; rebuild a `BasicIdentity` from it on demand.
    /// This is the backend session key the standing delegation ends at, and the
    /// `session_key` sent to II so app delegations end at it too.
    key_seed: [u8; 32],
    /// DER public key of the session key.
    pubkey_der: Vec<u8>,
    /// domain -> most recently derived per-app delegation.
    app_delegations: HashMap<String, AppDelegation>,
}

/// A cached on-demand per-app account delegation.
struct AppDelegation {
    user_key: Vec<u8>,
    chain: Vec<SignedDelegation>,
    expiration_ns: u64,
}

impl AppDelegation {
    /// Whether this cached delegation is still safe to reuse.
    fn fresh(&self) -> bool {
        self.expiration_ns > now_ns().saturating_add(REDERIVE_MARGIN_NS)
    }
}

#[derive(Clone, Default)]
pub struct Identities {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
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
                app_delegations: HashMap::new(),
            }
        });
    }

    /// The backend session key (its DER pubkey) and a `BasicIdentity` over it.
    async fn session_key(&self, session_id: &str) -> Option<([u8; 32], Vec<u8>)> {
        let sessions = self.sessions.read().await;
        let s = sessions.get(session_id)?;
        Some((s.key_seed, s.pubkey_der.clone()))
    }

    /// The connect-time **60-minute standing delegation** (`anchor -> backend
    /// session key`, issued for the MCP origin), as an `ic-agent` identity the
    /// backend signs II's account-derivation calls with.
    ///
    /// TODO(standing-credential): the II-side connect flow that mints this
    /// standing delegation is not landed yet. Once it is, this should return the
    /// `DelegatedIdentity` built from the chain captured at OpenID time:
    /// `DelegatedIdentity::new(anchor_user_key, Box::new(<backend BasicIdentity>),
    /// standing_chain)`. Until then it returns an explanatory error so callers
    /// surface the missing capability instead of silently calling anonymously.
    async fn standing_identity(&self, session_id: &str) -> Result<DelegatedIdentity, String> {
        self.ensure_session(session_id).await;
        let _ = self.session_key(session_id).await;
        Err(
            "no standing Internet Identity credential for this session yet: the connect-time \
             flow that obtains the 60-minute `anchor -> backend session key` delegation is not \
             deployed yet (TODO: standing_identity). On-demand app delegations cannot be derived \
             until it lands."
                .to_string(),
        )
    }

    /// Build the `ic-agent` identity for a domain, deriving the per-app account
    /// delegation on demand (and caching it) if there is no fresh cached one.
    pub async fn delegated_identity(
        &self,
        session_id: &str,
        domain: &str,
    ) -> Result<DelegatedIdentity, String> {
        self.ensure_session(session_id).await;

        // Reuse a cached, still-fresh delegation if present.
        if let Some(app) = self.cached_fresh(session_id, domain).await {
            return self.build_identity(session_id, &app).await;
        }

        // Otherwise derive a fresh one on demand against the II canister.
        let app = self.derive_app_delegation(session_id, domain).await?;
        let identity = self.build_identity(session_id, &app).await?;
        self.store(session_id, domain, app).await;
        Ok(identity)
    }

    async fn cached_fresh(&self, session_id: &str, domain: &str) -> Option<AppDelegation> {
        let sessions = self.sessions.read().await;
        let app = sessions.get(session_id)?.app_delegations.get(domain)?;
        if !app.fresh() {
            return None;
        }
        Some(AppDelegation {
            user_key: app.user_key.clone(),
            chain: app.chain.clone(),
            expiration_ns: app.expiration_ns,
        })
    }

    async fn store(&self, session_id: &str, domain: &str, app: AppDelegation) {
        let mut sessions = self.sessions.write().await;
        if let Some(s) = sessions.get_mut(session_id) {
            s.app_delegations.insert(domain.to_string(), app);
        }
    }

    /// Build a `DelegatedIdentity` for a derived app delegation: the chain ends
    /// at the backend session key, so the backend `BasicIdentity` signs.
    async fn build_identity(
        &self,
        session_id: &str,
        app: &AppDelegation,
    ) -> Result<DelegatedIdentity, String> {
        let (seed, _) = self
            .session_key(session_id)
            .await
            .ok_or("session vanished")?;
        let key = BasicIdentity::from_raw_key(&seed);
        DelegatedIdentity::new(app.user_key.clone(), Box::new(key), app.chain.clone())
            .map_err(|e| format!("invalid delegation chain: {e}"))
    }

    /// Derive a fresh per-app account delegation by calling II's
    /// `mcp_prepare_account_delegation` then `mcp_get_account_delegation`, AS the
    /// standing identity, with the backend session key as `session_key`.
    async fn derive_app_delegation(
        &self,
        session_id: &str,
        domain: &str,
    ) -> Result<AppDelegation, String> {
        let (_, session_key_der) = self
            .session_key(session_id)
            .await
            .ok_or("session vanished")?;
        let origin = target_origin(domain);
        let canister = ii_canister_id()?;

        // Call II AS the standing delegation identity (the anchor's MCP-origin
        // principal) — that's the caller II requires for account derivation.
        let standing = self.standing_identity(session_id).await?;
        let agent = Agent::builder()
            .with_url(IC_URL)
            .with_identity(standing)
            .build()
            .map_err(|e| format!("could not build II agent: {e}"))?;

        // mcp_prepare_account_delegation(target_origin, session_key, opt max_ttl_ns)
        //   -> record { user_key: blob; expiration: nat64 }
        let prepare_arg = Encode!(
            &origin,
            &session_key_der,
            &Some(APP_DELEGATION_TTL_NS)
        )
        .map_err(|e| format!("could not encode prepare args: {e}"))?;
        let prepared = agent
            .update(&canister, "mcp_prepare_account_delegation")
            .with_arg(prepare_arg)
            .call_and_wait()
            .await
            .map_err(|e| format!("mcp_prepare_account_delegation failed: {e}"))?;
        let prepared = Decode!(&prepared, PreparedDelegation)
            .map_err(|e| format!("could not decode prepare reply: {e}"))?;

        // mcp_get_account_delegation(target_origin, session_key, expiration)
        //   -> variant { Ok: SignedDelegation; Err: text }
        let get_arg = Encode!(&origin, &session_key_der, &prepared.expiration)
            .map_err(|e| format!("could not encode get args: {e}"))?;
        let got = agent
            .query(&canister, "mcp_get_account_delegation")
            .with_arg(get_arg)
            .call()
            .await
            .map_err(|e| format!("mcp_get_account_delegation failed: {e}"))?;
        let got = Decode!(&got, GetDelegationResult)
            .map_err(|e| format!("could not decode get reply: {e}"))?;
        let signed = match got {
            GetDelegationResult::Ok(d) => d,
            GetDelegationResult::Err(e) => {
                return Err(format!("II refused account delegation: {e}"))
            }
        };

        let chain = vec![signed.into_agent(&session_key_der)?];
        Ok(AppDelegation {
            user_key: prepared.user_key,
            chain,
            expiration_ns: prepared.expiration,
        })
    }
}

// ---- II candid contract (NOT yet deployed; built against this contract) ----

/// Reply of `mcp_prepare_account_delegation`.
#[derive(CandidType, Deserialize)]
struct PreparedDelegation {
    user_key: Vec<u8>,
    expiration: u64,
}

/// One delegation as returned by II's `mcp_get_account_delegation`.
#[derive(CandidType, Deserialize)]
struct IiDelegation {
    pubkey: Vec<u8>,
    expiration: u64,
    targets: Option<Vec<Principal>>,
}

/// `SignedDelegation` as returned by II's `mcp_get_account_delegation`.
#[derive(CandidType, Deserialize)]
struct IiSignedDelegation {
    delegation: IiDelegation,
    signature: Vec<u8>,
}

impl IiSignedDelegation {
    /// Convert into `ic-agent`'s `SignedDelegation`, checking that the
    /// delegation actually targets the backend session key (so the chain ends
    /// where we can sign).
    fn into_agent(self, session_key_der: &[u8]) -> Result<SignedDelegation, String> {
        if self.delegation.pubkey != session_key_der {
            return Err(
                "II delegation does not delegate to the backend session key".to_string(),
            );
        }
        Ok(SignedDelegation {
            delegation: Delegation {
                pubkey: self.delegation.pubkey,
                expiration: self.delegation.expiration,
                targets: self.delegation.targets,
            },
            signature: self.signature,
        })
    }
}

/// Result of `mcp_get_account_delegation : variant { Ok: SignedDelegation; Err: text }`.
#[derive(CandidType, Deserialize)]
enum GetDelegationResult {
    Ok(IiSignedDelegation),
    Err(String),
}

#[cfg(test)]
mod tests {
    use super::target_origin;

    #[test]
    fn remaps_gateway_domains_to_ic0_app() {
        assert_eq!(
            target_origin("rdmx6-jaaaa-aaaaa-aaadq-cai.icp0.io"),
            "https://rdmx6-jaaaa-aaaaa-aaadq-cai.ic0.app"
        );
        assert_eq!(
            target_origin("foo.icp.net"),
            "https://foo.ic0.app"
        );
    }

    #[test]
    fn passes_through_custom_domains() {
        assert_eq!(target_origin("oisy.com"), "https://oisy.com");
        assert_eq!(target_origin("https://oisy.com/app"), "https://oisy.com");
        assert_eq!(target_origin("http://oisy.com"), "https://oisy.com");
    }
}
