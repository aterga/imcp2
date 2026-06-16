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

/// Decode Candid reply bytes to textual Candid (Candid messages are self-describing).
#[wasm_bindgen]
pub fn decode_args(bytes: &[u8]) -> Result<String, JsError> {
    let args = candid::types::value::IDLArgs::from_bytes(bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(args.to_string())
}
