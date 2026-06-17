//! Browser-side Candid: encode textual Candid args to bytes and decode reply
//! bytes back to textual Candid, using the same Rust `candid` implementation the
//! server uses — compiled to WASM. Running this in the browser means the user
//! signs exactly the bytes encoded from the text they reviewed; the untrusted
//! server is never in the encode/decode path.

use wasm_bindgen::prelude::*;

/// Encode textual Candid arguments (e.g. `(record { amount = 5 })`) to bytes.
#[wasm_bindgen]
pub fn encode_args(text: &str) -> Result<Vec<u8>, JsError> {
    let args = candid_parser::parse_idl_args(text).map_err(|e| JsError::new(&e.to_string()))?;
    args.to_bytes().map_err(|e| JsError::new(&e.to_string()))
}

/// Decode Candid reply bytes to textual Candid, type-less (field names appear as
/// their wire-format hashes). Prefer `decode_rets_with_did` when an interface is
/// available.
#[wasm_bindgen]
pub fn decode_args(bytes: &[u8]) -> Result<String, JsError> {
    let args = candid::types::value::IDLArgs::from_bytes(bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(args.to_string())
}

/// Encode textual Candid args against a method's declared argument types (from
/// the canister's `.did`), coercing literals to the right Candid types.
#[wasm_bindgen]
pub fn encode_args_with_did(did: &str, method: &str, text: &str) -> Result<Vec<u8>, JsError> {
    let (env, actor) = load_service(did)?;
    let func = env.get_method(&actor, method).map_err(je)?;
    let args = candid_parser::parse_idl_args(text).map_err(je)?;
    args.to_bytes_with_types(&env, &func.args).map_err(je)
}

/// Decode reply bytes against a method's declared return types (from the `.did`),
/// recovering record/variant field names instead of hashes.
#[wasm_bindgen]
pub fn decode_rets_with_did(did: &str, method: &str, bytes: &[u8]) -> Result<String, JsError> {
    let (env, actor) = load_service(did)?;
    let func = env.get_method(&actor, method).map_err(je)?;
    let args = candid::types::value::IDLArgs::from_bytes_with_types(bytes, &env, &func.rets)
        .map_err(je)?;
    Ok(args.to_string())
}

fn load_service(did: &str) -> Result<(candid::TypeEnv, candid::types::Type), JsError> {
    let (env, actor) = candid_parser::utils::CandidSource::Text(did).load().map_err(je)?;
    let actor = actor.ok_or_else(|| JsError::new("no service type in .did"))?;
    Ok((env, actor))
}

fn je<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}
