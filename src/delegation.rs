//! Verify an Internet Identity login server-side: a delegation chain (rooted at
//! an II canister-signature key) plus a fresh signature over a server-issued
//! nonce by the leaf session key.
//!
//! This makes the principal the OpenID flow asserts **verified** rather than
//! browser-asserted, so anything keyed on it (per-principal session data, access
//! decisions) is sound. Funds are unaffected either way — that's enforced by the
//! IC at signing time, not here.
//!
//! Verification per delegation:
//!   message = 0x1A ++ "ic-request-auth-delegation" ++ repr_independent_hash({pubkey, expiration[, targets]})
//! signed by the previous key in the chain (root for the first delegation). The
//! root is an II canister signature, checked against the IC root key. The final
//! delegated-to key (the session key) must have signed the nonce.

use candid::Principal;
use ic_representation_independent_hash::{representation_independent_hash, Value};
use ic_signature_verification::verify_canister_sig;

/// DER-encoded IC mainnet root public key (BLS12-381 G2); raw key is the last 96 bytes.
const IC_ROOT_KEY_DER: &[u8; 133] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";

fn ic_root_key_raw() -> &'static [u8] {
    &IC_ROOT_KEY_DER[IC_ROOT_KEY_DER.len() - 96..]
}

// DER SubjectPublicKeyInfo prefixes for the two basic session-key algorithms
// auth-client uses. Matching the prefix lets us slice out the raw key without a
// full ASN.1 parser.
const ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// One signed delegation from a chain.
#[derive(Debug, Clone)]
pub struct SignedDelegation {
    /// The key this delegation delegates *to* (DER SubjectPublicKeyInfo).
    pub pubkey: Vec<u8>,
    /// Expiration in nanoseconds since the Unix epoch.
    pub expiration: u64,
    /// Optional canister-id restriction.
    pub targets: Option<Vec<Vec<u8>>>,
    /// Signature over this delegation by the previous key in the chain.
    pub signature: Vec<u8>,
}

/// Verify the chain + nonce signature; return the verified self-authenticating principal.
pub fn verify_login(
    nonce: &[u8],
    root_pubkey_der: &[u8],
    delegations: &[SignedDelegation],
    nonce_signature: &[u8],
    now_ns: u64,
) -> Result<Principal, String> {
    let principal = Principal::self_authenticating(root_pubkey_der);

    // Walk the chain: each delegation is signed by the previous key (root first).
    let mut signer_der = root_pubkey_der.to_vec();
    for d in delegations {
        if d.expiration <= now_ns {
            return Err("delegation expired".into());
        }
        let message = delegation_message(d);
        verify_chain_link(&signer_der, &message, &d.signature)?;
        signer_der = d.pubkey.clone();
    }

    // The leaf (session) key must have signed the server's nonce.
    verify_basic_sig(&signer_der, nonce, nonce_signature)
        .map_err(|e| format!("nonce signature invalid: {e}"))?;

    Ok(principal)
}

fn delegation_message(d: &SignedDelegation) -> Vec<u8> {
    let mut map = vec![
        ("pubkey".to_string(), Value::Bytes(d.pubkey.clone())),
        ("expiration".to_string(), Value::Number(d.expiration)),
    ];
    if let Some(targets) = &d.targets {
        map.push((
            "targets".to_string(),
            Value::Array(targets.iter().map(|t| Value::Bytes(t.clone())).collect()),
        ));
    }
    let hash = representation_independent_hash(&map);
    let mut message = b"\x1Aic-request-auth-delegation".to_vec();
    message.extend_from_slice(&hash);
    message
}

/// Verify a delegation's signature. A basic (Ed25519/P-256) signer is verified
/// directly; anything else is treated as an II canister signature and checked
/// against the IC root key.
fn verify_chain_link(signer_der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    if is_basic_key(signer_der) {
        verify_basic_sig(signer_der, message, signature)
    } else {
        verify_canister_sig(message, signature, signer_der, ic_root_key_raw())
            .map_err(|e| format!("canister signature invalid: {e}"))
    }
}

fn is_basic_key(der: &[u8]) -> bool {
    der.starts_with(ED25519_SPKI_PREFIX) || der.starts_with(P256_SPKI_PREFIX)
}

fn verify_basic_sig(der: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
    if let Some(raw) = der.strip_prefix(ED25519_SPKI_PREFIX) {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let key: [u8; 32] = raw.try_into().map_err(|_| "bad Ed25519 key length")?;
        let vk = VerifyingKey::from_bytes(&key).map_err(|e| format!("bad Ed25519 key: {e}"))?;
        let sig = Signature::from_slice(signature).map_err(|e| format!("bad Ed25519 sig: {e}"))?;
        vk.verify(message, &sig).map_err(|e| format!("Ed25519 verify failed: {e}"))
    } else if der.starts_with(P256_SPKI_PREFIX) {
        use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
        // The prefix includes the bit-string header and its 0x00 unused-bits byte,
        // so the SEC1 uncompressed point (0x04 ++ X ++ Y) starts right after it.
        let point = &der[P256_SPKI_PREFIX.len()..];
        let vk = VerifyingKey::from_sec1_bytes(point)
            .map_err(|e| format!("bad P-256 key: {e}"))?;
        let sig = Signature::from_slice(signature).map_err(|e| format!("bad P-256 sig: {e}"))?;
        vk.verify(message, &sig).map_err(|e| format!("P-256 verify failed: {e}"))
    } else {
        Err("unsupported session key algorithm".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ed25519_der(vk: &ed25519_dalek::VerifyingKey) -> Vec<u8> {
        [ED25519_SPKI_PREFIX, vk.as_bytes()].concat()
    }
    fn p256_der(vk: &p256::ecdsa::VerifyingKey) -> Vec<u8> {
        let point = vk.to_encoded_point(false); // 0x04 ++ X ++ Y
        [P256_SPKI_PREFIX, point.as_bytes()].concat()
    }

    /// Ed25519 root delegates to a P-256 session key, which signs the nonce.
    /// Exercises both the chain-link (basic Ed25519) and leaf (P-256) paths.
    #[test]
    fn verifies_valid_chain_and_derives_principal() {
        use ed25519_dalek::{Signer as _, SigningKey};
        use p256::ecdsa::{Signature as P256Sig, SigningKey as P256Key};

        let root = SigningKey::from_bytes(&[7u8; 32]);
        let root_der = ed25519_der(&root.verifying_key());
        let session = P256Key::from_bytes(&[9u8; 32].into()).unwrap();
        let session_der = p256_der(session.verifying_key());

        let now_ns = 1_000_000_000_000u64;
        let deleg = SignedDelegation {
            pubkey: session_der.clone(),
            expiration: now_ns + 3_600_000_000_000,
            targets: None,
            signature: vec![], // filled below
        };
        let msg = delegation_message(&deleg);
        let root_sig = root.sign(&msg).to_bytes().to_vec();
        let deleg = SignedDelegation { signature: root_sig, ..deleg };

        let nonce = b"server-issued-nonce";
        let nonce_sig: P256Sig = session.sign(nonce);
        let nonce_sig = nonce_sig.to_bytes().to_vec();

        let principal =
            verify_login(nonce, &root_der, &[deleg], &nonce_sig, now_ns).expect("should verify");
        assert_eq!(principal, Principal::self_authenticating(&root_der));
    }

    #[test]
    fn rejects_tampered_nonce_signature() {
        use ed25519_dalek::{Signer as _, SigningKey};
        let root = SigningKey::from_bytes(&[1u8; 32]);
        let root_der = ed25519_der(&root.verifying_key());
        let session = SigningKey::from_bytes(&[2u8; 32]);
        let session_der = ed25519_der(&session.verifying_key());
        let now_ns = 1_000_000_000_000u64;
        let mut deleg = SignedDelegation {
            pubkey: session_der,
            expiration: now_ns + 1_000_000_000,
            targets: None,
            signature: vec![],
        };
        deleg.signature = root.sign(&delegation_message(&deleg)).to_bytes().to_vec();
        let bad_sig = session.sign(b"a-different-nonce").to_bytes().to_vec();
        assert!(verify_login(b"the-real-nonce", &root_der, &[deleg], &bad_sig, now_ns).is_err());
    }

    #[test]
    fn rejects_expired_delegation() {
        use ed25519_dalek::{Signer as _, SigningKey};
        let root = SigningKey::from_bytes(&[3u8; 32]);
        let root_der = ed25519_der(&root.verifying_key());
        let session = SigningKey::from_bytes(&[4u8; 32]);
        let session_der = ed25519_der(&session.verifying_key());
        let now_ns = 2_000_000_000_000u64;
        let mut deleg = SignedDelegation {
            pubkey: session_der,
            expiration: now_ns - 1, // already expired
            targets: None,
            signature: vec![],
        };
        deleg.signature = root.sign(&delegation_message(&deleg)).to_bytes().to_vec();
        let nonce_sig = session.sign(b"n").to_bytes().to_vec();
        assert!(verify_login(b"n", &root_der, &[deleg], &nonce_sig, now_ns).is_err());
    }
}
