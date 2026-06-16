//! Best-effort discovery of the canisters behind a web domain served from the
//! Internet Computer, folding together the patterns we've seen across apps:
//!
//!   1. `x-ic-canister-id` response header — the frontend/asset canister. This
//!      is the one universal, authoritative signal (the HTTP gateway sets it).
//!   2. a runtime config asset (`/env.json`) carrying `*canister_id*` keys —
//!      e.g. Caffeine apps expose `backend_canister_id` here.
//!   3. canister-id literals in the JS bundle, preferring labelled
//!      `*_CANISTER_ID` constants — e.g. dfx/Vite apps like OISY bake
//!      `IC_BACKEND_CANISTER_ID`, `IC_SIGNER_CANISTER_ID`, etc.
//!
//! There is NO authoritative reverse lookup for "this site's backend" — only
//! the frontend (1) is certain. (2) and (3) are mined from client code, so each
//! result carries its provenance and the caller decides (and should confirm
//! with `get_candid`).

use std::collections::BTreeMap;

use candid::Principal;
use regex::Regex;
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct Found {
    pub canister_id: String,
    /// A human label if one was attached (env.json key, bundle constant name,
    /// or "frontend"); None for a bare bundle literal.
    pub label: Option<String>,
    /// Where it was found: "header", "env.json", "bundle:<LABEL>", "bundle".
    pub sources: Vec<String>,
}

/// Canister textual principals: four 5-char base32 groups + the `cai` suffix.
fn canister_re() -> Regex {
    Regex::new(r"[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-cai").unwrap()
}

/// Extract `(canister_id, key)` pairs from an `/env.json` body: any object key
/// whose name mentions "canister" with a string value.
fn canisters_from_env_json(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(text) {
        for (k, v) in map {
            if k.to_lowercase().contains("canister") {
                if let Some(s) = v.as_str() {
                    out.push((s.to_string(), k));
                }
            }
        }
    }
    out
}

fn normalize(domain: &str) -> String {
    let d = domain.trim().trim_end_matches('/');
    if d.starts_with("http://") || d.starts_with("https://") {
        d.to_string()
    } else {
        format!("https://{d}")
    }
}

fn add(found: &mut BTreeMap<String, Found>, id: &str, label: Option<String>, source: String) {
    // Drop false positives by validating as a real principal.
    if Principal::from_text(id).is_err() {
        return;
    }
    let entry = found.entry(id.to_string()).or_insert_with(|| Found {
        canister_id: id.to_string(),
        label: None,
        sources: Vec::new(),
    });
    if entry.label.is_none() {
        entry.label = label;
    }
    if !entry.sources.contains(&source) {
        entry.sources.push(source);
    }
}

pub async fn discover(domain: &str) -> Result<Vec<Found>, String> {
    let base = normalize(domain);
    let client = reqwest::Client::builder()
        .user_agent("ic-mcp-discover/0.1")
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| format!("http client: {e}"))?;

    let mut found: BTreeMap<String, Found> = BTreeMap::new();

    // 1. Frontend via the gateway header (and keep the HTML for bundle mining).
    let resp = client
        .get(&base)
        .send()
        .await
        .map_err(|e| format!("could not reach {base}: {e}"))?;
    if let Some(id) = resp
        .headers()
        .get("x-ic-canister-id")
        .and_then(|v| v.to_str().ok())
    {
        add(&mut found, id, Some("frontend".into()), "header".into());
    }
    let html = resp.text().await.unwrap_or_default();

    // 2. Runtime config: /env.json with *canister_id* keys (e.g. Caffeine apps).
    if let Ok(resp) = client.get(format!("{base}/env.json")).send().await {
        if resp.status().is_success() {
            if let Ok(text) = resp.text().await {
                for (id, label) in canisters_from_env_json(&text) {
                    add(&mut found, &id, Some(label), "env.json".into());
                }
            }
        }
    }

    // 3. JS bundle: labelled constants first, then any bare canister literals.
    let mut blob = html.clone();
    let script_re = Regex::new(r#"["'](/[^"'<> ]+?\.js)["']"#).unwrap();
    let mut scripts: Vec<String> = script_re
        .captures_iter(&html)
        .map(|c| c[1].to_string())
        .collect();
    scripts.sort();
    scripts.dedup();
    for s in scripts.iter().take(20) {
        if let Ok(resp) = client.get(format!("{base}{s}")).send().await {
            if let Ok(t) = resp.text().await {
                blob.push('\n');
                blob.push_str(&t);
            }
        }
    }

    let label_re = Regex::new(
        r#"([A-Z][A-Z0-9_]*CANISTER_ID)["'\s:=]+([a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-[a-z0-9]{5}-cai)"#,
    )
    .unwrap();
    for c in label_re.captures_iter(&blob) {
        let label = c[1].to_string();
        add(&mut found, &c[2], Some(label.clone()), format!("bundle:{label}"));
    }
    for m in canister_re().find_iter(&blob) {
        add(&mut found, m.as_str(), None, "bundle".into());
    }

    // Order: header (frontend) first, then env.json, then labelled bundle, then bare.
    let mut out: Vec<Found> = found.into_values().collect();
    out.sort_by_key(|f| {
        if f.sources.iter().any(|s| s == "header") {
            0
        } else if f.sources.iter().any(|s| s == "env.json") {
            1
        } else if f.sources.iter().any(|s| s.starts_with("bundle:")) {
            2
        } else {
            3
        }
    });
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Live network test against a stable public IC app (OISY).
    #[tokio::test]
    async fn discovers_oisy_frontend_and_backend() {
        let found = discover("oisy.com").await.expect("discover");
        let ids: Vec<&str> = found.iter().map(|f| f.canister_id.as_str()).collect();
        // Frontend from the gateway header.
        assert!(
            ids.contains(&"cha4i-riaaa-aaaan-qeccq-cai"),
            "frontend not found: {ids:?}"
        );
        // Backend from the labelled bundle constant (IC_BACKEND_CANISTER_ID).
        assert!(
            ids.contains(&"doked-biaaa-aaaar-qag2a-cai"),
            "backend not found: {ids:?}"
        );
    }

    // The Caffeine env.json pattern (offline so it doesn't flake when drafts expire).
    #[test]
    fn env_json_yields_backend_canister_id() {
        let body = r#"{"backend_canister_id":"dmp3l-2yaaa-aaaae-aamva-cai",
                       "backend_host":"https://icp-api.io",
                       "project_id":"019ed114-d95a-71aa-bb1f-2410200446d2"}"#;
        let got = canisters_from_env_json(body);
        assert_eq!(got.len(), 1, "only the canister key should match: {got:?}");
        assert_eq!(got[0].0, "dmp3l-2yaaa-aaaae-aamva-cai");
        assert_eq!(got[0].1, "backend_canister_id");
    }
}
