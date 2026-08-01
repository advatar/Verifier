#![forbid(unsafe_code)]

use hybrid_pq::{
    envelope::{decode_public_key, decode_signature},
    tbs::HybridPurpose,
};
use hybrid_pq_verifier::{verify_es256, verify_ml_dsa_65};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

const TBS_HEX: &str = include_str!("../../../docs/test-vectors/hybrid-pq-v1-component-tbs.hex");
const PUBLIC_KEY_HEX: &str =
    include_str!("../../../docs/test-vectors/hybrid-pq-v1-public-key-envelope.hex");
const SIGNATURE_HEX: &str =
    include_str!("../../../docs/test-vectors/hybrid-pq-v1-signature-envelope.hex");
const MUTATIONS_JSON: &str =
    include_str!("../../../docs/test-vectors/hybrid-pq-v1-component-mutations.json");

fn decode_hex(value: &str) -> Vec<u8> {
    let value = value.trim().as_bytes();
    assert_eq!(value.len() % 2, 0);
    value
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte| match byte {
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
    usize::try_from(value[field].as_u64().unwrap()).unwrap()
}

fn u8_value(value: &Value, field: &str) -> u8 {
    u8::try_from(value[field].as_u64().unwrap()).unwrap()
}

fn apply_operations(mut bytes: Vec<u8>, operations: &[Value]) -> Vec<u8> {
    for operation in operations {
        match operation["op"].as_str().unwrap() {
            "xor" => {
                bytes[usize_value(operation, "offset")] ^= u8_value(operation, "value");
            }
            "truncate" => {
                let new_len = bytes.len() - usize_value(operation, "count");
                bytes.truncate(new_len);
            }
            "append" => bytes.extend(decode_hex(operation["hex"].as_str().unwrap())),
            "replace" => {
                let offset = usize_value(operation, "offset");
                let delete = usize_value(operation, "delete");
                bytes.splice(
                    offset..offset + delete,
                    decode_hex(operation["hex"].as_str().unwrap()),
                );
            }
            "remove" => {
                let offset = usize_value(operation, "offset");
                let count = usize_value(operation, "count");
                bytes.drain(offset..offset + count);
            }
            _ => panic!("unknown mutation"),
        }
    }
    bytes
}

#[test]
fn verifies_the_shared_component_corpus_atomically() {
    let tbs_bytes = decode_hex(TBS_HEX);
    let public_envelope = decode_hex(PUBLIC_KEY_HEX);
    let signature_envelope = decode_hex(SIGNATURE_HEX);
    let public_key = decode_public_key(&public_envelope).unwrap();
    let signature = decode_signature(&signature_envelope).unwrap();

    assert_eq!(signature.purpose(), HybridPurpose::TestSdJwtWrapperV1);
    verify_es256(
        public_key.classical(),
        &tbs_bytes,
        signature.signature().classical(),
    )
    .unwrap();
    verify_ml_dsa_65(
        public_key.post_quantum(),
        &tbs_bytes,
        signature.signature().post_quantum(),
    )
    .unwrap();
    assert_eq!(
        sha256_hex(&tbs_bytes),
        "ebdf4ddf9bdd7f72172f623ae94fa19dad62023574d1d68c62aff6a52c2b2805"
    );
    assert_eq!(
        sha256_hex(&public_envelope),
        "6f252c80edfb3a902ea26abe6eabd98e883f4828238810a07be165653e4eb42c"
    );
    assert_eq!(
        sha256_hex(&signature_envelope),
        "ff348f5a043989ee5f2fb329bc25f5778f8750b5685041eaf8753db90eb386a7"
    );
}

#[test]
fn rejects_all_twelve_shared_component_mutations() {
    let tbs = decode_hex(TBS_HEX);
    let public_envelope = decode_hex(PUBLIC_KEY_HEX);
    let signature_envelope = decode_hex(SIGNATURE_HEX);
    let public_key = decode_public_key(&public_envelope).unwrap();
    let mutations: Value = serde_json::from_str(MUTATIONS_JSON).unwrap();
    let mutations = mutations["mutations"].as_array().unwrap();
    assert_eq!(mutations.len(), 12);

    for mutation in mutations {
        let target = mutation["target"].as_str().unwrap();
        let base = if target == "public-key-envelope" {
            public_envelope.clone()
        } else {
            signature_envelope.clone()
        };
        let mutated = apply_operations(base, mutation["operations"].as_array().unwrap());
        let rejected = if target == "public-key-envelope" {
            decode_public_key(&mutated).is_err()
        } else {
            match decode_signature(&mutated) {
                Err(_) => true,
                Ok(decoded) => {
                    verify_es256(
                        public_key.classical(),
                        &tbs,
                        decoded.signature().classical(),
                    )
                    .is_err()
                        || verify_ml_dsa_65(
                            public_key.post_quantum(),
                            &tbs,
                            decoded.signature().post_quantum(),
                        )
                        .is_err()
                }
            }
        };
        assert!(rejected, "{} must reject", mutation["name"]);
    }
}
