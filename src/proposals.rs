//! Shared store of candidate canister calls the LLM *proposes* and the user
//! *signs* on `/app`. The server only brokers the proposal and decodes the
//! reply — it never signs. The browser signs with the II identity and submits
//! directly to the IC, so the untrusted server is not in the signing path.
//!
//! Calls are fully generic: any canister, any method, arguments as textual
//! Candid (mirroring the `call_canister` tool). The proposal carries only the
//! textual Candid — the browser encodes it locally (Rust `candid` compiled to
//! WASM) before signing, so what the user reviews is exactly what gets signed
//! (what-you-see-is-what-you-sign), and decodes the reply locally too. The
//! untrusted server is never in the encode/decode/sign path.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone, Serialize)]
pub struct Proposal {
    pub id: String,
    pub canister_id: String,
    pub method: String,
    /// Arguments in textual Candid — what the human reviews and the browser encodes.
    pub args: String,
    pub is_query: bool,
    pub proposer: String,
    /// The canister's Candid interface, if available, so the browser can encode
    /// args and decode the reply *with types* (recovering field names).
    pub did: Option<String>,
    /// "pending" | "done" | "failed"
    pub status: String,
    pub result: Option<String>,
    pub created_ns: u64,
}

#[derive(Clone, Default)]
pub struct Proposals(Arc<RwLock<HashMap<String, Proposal>>>);

impl Proposals {
    #[allow(clippy::too_many_arguments)]
    pub async fn create_call(
        &self,
        canister_id: String,
        method: String,
        args: String,
        is_query: bool,
        proposer: String,
        did: Option<String>,
    ) -> Proposal {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
        let proposal = Proposal {
            id: format!("prop-{}", Uuid::new_v4()),
            canister_id,
            method,
            args,
            is_query,
            proposer,
            did,
            status: "pending".to_string(),
            result: None,
            created_ns: now,
        };
        self.0.write().await.insert(proposal.id.clone(), proposal.clone());
        proposal
    }

    pub async fn get(&self, id: &str) -> Option<Proposal> {
        self.0.read().await.get(id).cloned()
    }

    /// Wait (bounded) for a proposal to leave the `pending` state — so the LLM
    /// can call `check_proposal` once after the user signs and get the result,
    /// rather than polling in a loop. Returns the latest state on timeout.
    pub async fn wait_for_result(&self, id: &str, timeout: Duration) -> Option<Proposal> {
        let deadline = timeout.as_millis() / 500;
        for _ in 0..deadline.max(1) {
            let p = self.get(id).await?;
            if p.status != "pending" {
                return Some(p);
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        self.get(id).await
    }

    pub async fn list_pending(&self) -> Vec<Proposal> {
        let mut v: Vec<_> = self
            .0
            .read()
            .await
            .values()
            .filter(|p| p.status == "pending")
            .cloned()
            .collect();
        v.sort_by_key(|p| p.created_ns);
        v
    }

    async fn set_result(&self, id: &str, status: &str, result: Option<String>) -> bool {
        let mut map = self.0.write().await;
        let Some(p) = map.get_mut(id) else { return false };
        p.status = status.to_string();
        p.result = result;
        true
    }
}

// ---- Browser-facing API (called by /app, not by MCP clients) -----------

/// GET /api/proposals — pending proposals for the signer to review.
pub async fn list_pending(State(store): State<Proposals>) -> Json<Vec<Proposal>> {
    Json(store.list_pending().await)
}

#[derive(Deserialize)]
pub struct ResultBody {
    /// true if the signed call succeeded.
    ok: bool,
    /// Outcome: the browser-decoded textual Candid reply, or an error message.
    detail: String,
}

/// POST /api/proposals/:id/result — /app reports the signed call's outcome
/// (already decoded to textual Candid in the browser).
pub async fn submit_result(
    State(store): State<Proposals>,
    Path(id): Path<String>,
    Json(body): Json<ResultBody>,
) -> Response {
    let status = if body.ok { "done" } else { "failed" };
    if store.set_result(&id, status, Some(body.detail)).await {
        Json(serde_json::json!({ "ok": true })).into_response()
    } else {
        (axum::http::StatusCode::NOT_FOUND, "unknown proposal").into_response()
    }
}
