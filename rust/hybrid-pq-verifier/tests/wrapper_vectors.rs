#![forbid(unsafe_code)]

use hybrid_pq::{
    envelope::decode_public_key,
    tbs::{HybridContext, HybridPurpose},
    wrapper::{HybridCredentialWrapper, WrapperBinding, decode_credential_wrapper},
};
use hybrid_pq_verifier::{
    HybridCredentialVerificationInput, verify_hybrid_credential_wrapper_atomic,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

const TBS_HEX: &str = include_str!("../../../docs/test-vectors/hybrid-pq-v1-component-tbs.hex");
const PUBLIC_KEY_ENVELOPE_HEX: &str =
    include_str!("../../../docs/test-vectors/hybrid-pq-v1-public-key-envelope.hex");
const WRAPPER_ENVELOPE_HEX: &str =
    include_str!("../../../docs/test-vectors/hybrid-pq-v1-wrapper-envelope.hex");
const MUTATIONS_JSON: &str =
    include_str!("../../../docs/test-vectors/hybrid-pq-v1-wrapper-mutations.json");

const EXPECTED_CLASSICAL_KEY_ID: &str = "shared-classical-kid-v1";
const EXPECTED_PQ_KEY_ID: &str = "shared-pq-kid-v1";
const EXPECTED_GENERATION: u64 = 9;

fn corpus_context() -> HybridContext {
    HybridContext {
        wallet_identity: b"wallet-holder-thumbprint".to_vec(),
        issuer_identity: Some(b"https://issuer.example".to_vec()),
        key_generation: EXPECTED_GENERATION,
        transaction_id: Some(b"transaction-123".to_vec()),
        session_id: None,
        audience: Some(b"https://issuer.example".to_vec()),
        nonce: (0_u8..32).collect(),
        created_at_epoch_seconds: 1_700_000_000,
        expires_at_epoch_seconds: 1_700_003_600,
        transcript_hash: None,
    }
}

fn binding() -> WrapperBinding {
    WrapperBinding {
        classical_key_id: EXPECTED_CLASSICAL_KEY_ID.into(),
        pq_key_id: EXPECTED_PQ_KEY_ID.into(),
        generation: EXPECTED_GENERATION,
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    let value = value.trim().as_bytes();
    assert_eq!(value.len() % 2, 0, "hex input length");
    value
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("invalid hex digit"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn sha256_hex(value: &[u8]) -> String {
    Sha256::digest(value)
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            write!(output, "{byte:02x}").unwrap();
            output
        })
}

fn usize_value(value: &Value, field: &str) -> usize {
    usize::try_from(value[field].as_u64().expect("integer mutation field")).unwrap()
}

fn u8_value(value: &Value, field: &str) -> u8 {
    u8::try_from(value[field].as_u64().expect("byte mutation field")).unwrap()
}

fn apply_operations(mut bytes: Vec<u8>, operations: &[Value]) -> Vec<u8> {
    for operation in operations {
        match operation["op"].as_str().expect("mutation operation") {
            "xor" => {
                let offset = usize_value(operation, "offset");
                bytes[offset] ^= u8_value(operation, "value");
            }
            "truncate" => {
                let count = usize_value(operation, "count");
                bytes.truncate(bytes.len() - count);
            }
            "append" => {
                bytes
                    .extend_from_slice(&decode_hex(operation["hex"].as_str().expect("append hex")));
            }
            "replace" => {
                let offset = usize_value(operation, "offset");
                let delete = usize_value(operation, "delete");
                bytes.splice(
                    offset..offset + delete,
                    decode_hex(operation["hex"].as_str().expect("replace hex")),
                );
            }
            "remove" => {
                let offset = usize_value(operation, "offset");
                let count = usize_value(operation, "count");
                bytes.drain(offset..offset + count);
            }
            _ => panic!("unknown mutation operation"),
        }
    }
    bytes
}

fn corpus() -> (Vec<u8>, HybridCredentialWrapper, hybrid_pq::HybridPublicKey) {
    let wrapper_envelope = decode_hex(WRAPPER_ENVELOPE_HEX);
    let wrapper = decode_credential_wrapper(&wrapper_envelope).expect("frozen wrapper envelope");
    let public_key = decode_public_key(&decode_hex(PUBLIC_KEY_ENVELOPE_HEX))
        .expect("frozen public-key envelope");
    (wrapper_envelope, wrapper, public_key)
}

fn accepts(candidate: &[u8], public_key: &hybrid_pq::HybridPublicKey) -> bool {
    let public_key_envelope = hybrid_pq::envelope::encode_public_key(public_key);
    verify_hybrid_credential_wrapper_atomic(&HybridCredentialVerificationInput {
        wrapper_envelope: candidate,
        public_key_envelope: &public_key_envelope,
        expected_purpose: HybridPurpose::TestSdJwtWrapperV1,
        binding: &binding(),
        context: &corpus_context(),
    })
    .is_ok()
}

#[test]
fn verifies_the_vcissuer_and_wallet_wrapper_corpus() {
    let (wrapper_envelope, wrapper, public_key) = corpus();
    assert_eq!(wrapper.purpose(), HybridPurpose::TestSdJwtWrapperV1);
    assert_eq!(wrapper.classical_key_id(), EXPECTED_CLASSICAL_KEY_ID);
    assert_eq!(wrapper.pq_key_id(), EXPECTED_PQ_KEY_ID);
    assert_eq!(wrapper.generation(), EXPECTED_GENERATION);
    assert_eq!(wrapper.disclosures().len(), 2);
    assert_eq!(
        wrapper.tbs(&corpus_context()).unwrap().as_bytes(),
        decode_hex(TBS_HEX)
    );
    assert!(accepts(&wrapper_envelope, &public_key));
    assert_eq!(
        sha256_hex(WRAPPER_ENVELOPE_HEX.as_bytes()),
        "ab61da190318f05e7d659e1477c0694e3499d141a5c748f6b0b19fef908195cb"
    );
    assert_eq!(
        sha256_hex(MUTATIONS_JSON.as_bytes()),
        "46926357600682028a5be30d3486eba3201a01ec8b65ba43d80287d5c710363f"
    );
}

#[test]
fn rejects_every_shared_wrapper_mutation() {
    let (wrapper_envelope, _, public_key) = corpus();
    let mutations: Value = serde_json::from_str(MUTATIONS_JSON).expect("shared mutations");
    let mutation_list = mutations["mutations"].as_array().expect("mutation list");
    assert_eq!(mutation_list.len(), 21, "complete mutation corpus");

    for mutation in mutation_list {
        let mutated = apply_operations(
            wrapper_envelope.clone(),
            mutation["operations"].as_array().expect("operations"),
        );
        assert!(
            !accepts(&mutated, &public_key),
            "{} must reject",
            mutation["name"]
        );
    }
}

#[test]
fn trusted_binding_is_mandatory() {
    let (wrapper_envelope, _, public_key) = corpus();
    let public_key_envelope = hybrid_pq::envelope::encode_public_key(&public_key);
    for wrong_binding in [
        WrapperBinding {
            classical_key_id: "wrong-classical-key".into(),
            ..binding()
        },
        WrapperBinding {
            pq_key_id: "wrong-pq-key".into(),
            ..binding()
        },
        WrapperBinding {
            generation: EXPECTED_GENERATION + 1,
            ..binding()
        },
    ] {
        assert!(
            verify_hybrid_credential_wrapper_atomic(&HybridCredentialVerificationInput {
                wrapper_envelope: &wrapper_envelope,
                public_key_envelope: &public_key_envelope,
                expected_purpose: HybridPurpose::TestSdJwtWrapperV1,
                binding: &wrong_binding,
                context: &corpus_context(),
            })
            .is_err()
        );
    }
}
