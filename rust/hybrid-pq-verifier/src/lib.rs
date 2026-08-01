#![forbid(unsafe_code)]
//! Verification backend for the isolated `euwallet-hybrid-pq-v1` profile.
//!
//! Ported from the `../EUWallet` `crypto-backend` atomic verifier. Acceptance
//! is atomic: the single entry point [`verify_hybrid_signature_atomic`]
//! validates strict envelopes, canonical re-encoding, profile and purpose
//! binding, key identity and generation, context policy, replay, freshness,
//! and downgrade state before both the ES256 and ML-DSA-65 components are
//! verified over one internally rebuilt to-be-signed byte string. No partial
//! component result is ever exposed.

use core::fmt;

use hybrid_pq::{
    ES256_PUBLIC_KEY_BYTES, ES256_SIGNATURE_BYTES, HybridComponent, HybridCryptoError,
    HybridErrorClass, HybridKeyRef, HybridMismatch, HybridPublicKey, HybridSignature,
    HybridSignatureProfile, HybridVerifier, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES,
    envelope::{
        EnvelopeError, decode_public_key, decode_signature, encode_public_key, encode_signature,
    },
    tbs::{HybridContext, HybridPurpose, HybridTbs},
};
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Signature as MlDsaSignature, Verifier, VerifyingKey};
use p256::ecdsa::signature::Verifier as EcdsaVerifierTrait;
use p256::ecdsa::{Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};

/// Public, non-secret failures with no backend diagnostic details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExperimentalPqError {
    InvalidPublicKey,
    InvalidSignature,
    VerificationFailed,
}

/// Generic external rejection with only a bounded, secret-free diagnostic
/// class for local tests and telemetry. No component-success state or backend
/// detail is exposed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HybridVerificationRejected(HybridErrorClass);

impl HybridVerificationRejected {
    #[must_use]
    pub fn diagnostic_class(self) -> HybridErrorClass {
        self.0
    }
}

impl fmt::Display for HybridVerificationRejected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("hybrid signature rejected")
    }
}

impl std::error::Error for HybridVerificationRejected {}

/// Complete inputs for the one atomic verification entry point.
/// `resolved_key_ref` identifies the trusted logical key that supplied the
/// complete public-key envelope; `expected_key_ref` is the identity/generation
/// authorized by the protocol transaction.
pub struct HybridVerificationInput<'a> {
    pub signature_envelope: &'a [u8],
    pub public_key_envelope: &'a [u8],
    pub resolved_key_ref: &'a HybridKeyRef,
    pub expected_key_ref: &'a HybridKeyRef,
    pub expected_profile: HybridSignatureProfile,
    pub expected_purpose: HybridPurpose,
    pub context: &'a HybridContext,
    pub payload: &'a [u8],
    pub expected_audience: Option<&'a [u8]>,
    pub expected_nonce: &'a [u8],
    pub seen_nonces: &'a [Vec<u8>],
    pub now_epoch_seconds: u64,
    pub downgrade_attempted: bool,
}

/// Parse, bind, reconstruct, verify and apply policy without exposing partial
/// component results.
///
/// # Errors
///
/// Fails closed with a single generic rejection; only a bounded diagnostic
/// class is attached for local tests and telemetry.
pub fn verify_hybrid_signature_atomic(
    input: &HybridVerificationInput<'_>,
) -> Result<(), HybridVerificationRejected> {
    let fail = HybridVerificationRejected;
    let signature_envelope = decode_signature(input.signature_envelope)
        .map_err(|error| fail(envelope_diagnostic(error)))?;
    let public_key = decode_public_key(input.public_key_envelope)
        .map_err(|error| fail(envelope_diagnostic(error)))?;

    // Re-encoding is a second, explicit canonicality invariant at the
    // orchestration boundary.
    if encode_signature(&signature_envelope) != input.signature_envelope
        || encode_public_key(&public_key) != input.public_key_envelope
    {
        return Err(fail(HybridErrorClass::NonCanonicalInput));
    }
    let signature = signature_envelope.signature();
    if input.expected_profile != HybridSignatureProfile::Es256MlDsa65V1
        || public_key.profile() != input.expected_profile
        || signature.profile() != input.expected_profile
        || signature_envelope.purpose() != input.expected_purpose
    {
        return Err(fail(HybridErrorClass::Mismatch));
    }
    if input.resolved_key_ref.identity() != input.expected_key_ref.identity() {
        return Err(fail(
            HybridCryptoError::Mismatch {
                field: HybridMismatch::Identity,
            }
            .class(),
        ));
    }
    if input.resolved_key_ref.generation() != input.expected_key_ref.generation()
        || input.context.key_generation != input.expected_key_ref.generation()
    {
        return Err(fail(
            HybridCryptoError::Mismatch {
                field: HybridMismatch::Generation,
            }
            .class(),
        ));
    }
    if input.context.wallet_identity != input.expected_key_ref.identity().as_bytes()
        || input.context.audience.as_deref() != input.expected_audience
        || input.context.nonce != input.expected_nonce
        || input
            .seen_nonces
            .iter()
            .any(|nonce| nonce == input.expected_nonce)
        || input.context.created_at_epoch_seconds > input.now_epoch_seconds
        || input.context.expires_at_epoch_seconds <= input.now_epoch_seconds
    {
        return Err(fail(HybridErrorClass::PolicyDenied));
    }
    if input.downgrade_attempted {
        return Err(fail(HybridErrorClass::DowngradeDetected));
    }

    let tbs = HybridTbs::build(
        input.expected_profile,
        input.expected_purpose,
        input.context,
        input.payload,
    )
    .map_err(|error| fail(error.class()))?;
    verify_es256(
        public_key.classical(),
        tbs.as_bytes(),
        signature.classical(),
    )
    .map_err(|_| fail(HybridErrorClass::VerificationFailure))?;
    verify_ml_dsa_65(
        public_key.post_quantum(),
        tbs.as_bytes(),
        signature.post_quantum(),
    )
    .map_err(|_| fail(HybridErrorClass::VerificationFailure))?;
    Ok(())
}

fn envelope_diagnostic(error: EnvelopeError) -> HybridErrorClass {
    match error {
        EnvelopeError::UnsupportedProfile => HybridErrorClass::UnsupportedProfile,
        EnvelopeError::MalformedComponent => HybridErrorClass::MalformedComponent,
        EnvelopeError::TooLarge => HybridErrorClass::ResourceLimitExceeded,
        _ => HybridErrorClass::NonCanonicalInput,
    }
}

/// Strict ES256 verification over a fixed 64-byte `r ‖ s` signature and a
/// 65-byte uncompressed SEC1 public key.
///
/// # Errors
///
/// Fails on any non-frozen component size, undecodable key or signature, or a
/// signature that does not verify.
pub fn verify_es256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ExperimentalPqError> {
    if public_key.len() != ES256_PUBLIC_KEY_BYTES {
        return Err(ExperimentalPqError::InvalidPublicKey);
    }
    if signature.len() != ES256_SIGNATURE_BYTES {
        return Err(ExperimentalPqError::InvalidSignature);
    }
    let key = EcdsaVerifyingKey::from_sec1_bytes(public_key)
        .map_err(|_| ExperimentalPqError::InvalidPublicKey)?;
    let signature =
        EcdsaSignature::from_slice(signature).map_err(|_| ExperimentalPqError::InvalidSignature)?;
    key.verify(message, &signature)
        .map_err(|_| ExperimentalPqError::VerificationFailed)
}

/// Strict ML-DSA-65 verification.
///
/// # Errors
///
/// Fails on any non-frozen component size, undecodable key or signature, or a
/// signature that does not verify.
pub fn verify_ml_dsa_65(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), ExperimentalPqError> {
    if public_key.len() != ML_DSA_65_PUBLIC_KEY_BYTES {
        return Err(ExperimentalPqError::InvalidPublicKey);
    }
    if signature.len() != ML_DSA_65_SIGNATURE_BYTES {
        return Err(ExperimentalPqError::InvalidSignature);
    }
    let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(public_key)
        .map_err(|_| ExperimentalPqError::InvalidPublicKey)?;
    let key = VerifyingKey::<MlDsa65>::decode(&encoded);
    let signature = MlDsaSignature::<MlDsa65>::try_from(signature)
        .map_err(|_| ExperimentalPqError::InvalidSignature)?;
    key.verify(message, &signature)
        .map_err(|_| ExperimentalPqError::VerificationFailed)
}

/// RustCrypto-backed implementation of the isolated [`HybridVerifier`] trait.
pub struct RustCryptoHybridVerifier;

impl HybridVerifier for RustCryptoHybridVerifier {
    fn verify_hybrid(
        &self,
        key: &HybridPublicKey,
        hybrid_tbs: &HybridTbs,
        signature: &HybridSignature,
    ) -> Result<(), HybridCryptoError> {
        if key.profile() != signature.profile() {
            return Err(HybridCryptoError::Mismatch {
                field: HybridMismatch::Profile,
            });
        }
        verify_es256(
            key.classical(),
            hybrid_tbs.as_bytes(),
            signature.classical(),
        )
        .map_err(|_| HybridCryptoError::VerificationFailure {
            component: HybridComponent::Classical,
        })?;
        verify_ml_dsa_65(
            key.post_quantum(),
            hybrid_tbs.as_bytes(),
            signature.post_quantum(),
        )
        .map_err(|_| HybridCryptoError::VerificationFailure {
            component: HybridComponent::PostQuantum,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hybrid_pq::envelope::HybridSignatureEnvelope;
    use ml_dsa::Keypair;
    use ml_dsa::signature::Signer as MlDsaSigner;
    use p256::ecdsa::SigningKey as EcdsaSigningKey;
    use p256::ecdsa::signature::Signer as EcdsaSigner;
    use sha2::{Digest, Sha256};

    struct VerificationFixture {
        signature_envelope: Vec<u8>,
        public_key_envelope: Vec<u8>,
        resolved: HybridKeyRef,
        expected: HybridKeyRef,
        context: HybridContext,
        payload: Vec<u8>,
    }

    impl VerificationFixture {
        fn input(&self) -> HybridVerificationInput<'_> {
            HybridVerificationInput {
                signature_envelope: &self.signature_envelope,
                public_key_envelope: &self.public_key_envelope,
                resolved_key_ref: &self.resolved,
                expected_key_ref: &self.expected,
                expected_profile: HybridSignatureProfile::Es256MlDsa65V1,
                expected_purpose: HybridPurpose::WalletExportV1,
                context: &self.context,
                payload: &self.payload,
                expected_audience: None,
                expected_nonce: &self.context.nonce,
                seen_nonces: &[],
                now_epoch_seconds: 1_700_000_010,
                downgrade_attempted: false,
            }
        }
    }

    fn ml_dsa_signing_key(seed_fill: u8) -> ml_dsa::SigningKey<MlDsa65> {
        let seed = ml_dsa::Seed::try_from(&[seed_fill; 32][..]).expect("32-byte seed");
        ml_dsa::SigningKey::from_seed(&seed)
    }

    fn verification_fixture_with(seed_fill: u8) -> VerificationFixture {
        let profile = HybridSignatureProfile::Es256MlDsa65V1;
        let purpose = HybridPurpose::WalletExportV1;
        let context = HybridContext {
            wallet_identity: b"wallet-key".to_vec(),
            issuer_identity: None,
            key_generation: 7,
            transaction_id: None,
            session_id: None,
            audience: None,
            nonce: (0_u8..16).collect(),
            created_at_epoch_seconds: 1_700_000_000,
            expires_at_epoch_seconds: 1_700_000_100,
            transcript_hash: None,
        };
        let payload = b"export-payload".to_vec();
        let tbs = HybridTbs::build(profile, purpose, &context, &payload).unwrap();

        let classical = EcdsaSigningKey::from_slice(&[seed_fill; 32]).unwrap();
        let classical_signature: EcdsaSignature = classical.sign(tbs.as_bytes());
        let post_quantum = ml_dsa_signing_key(seed_fill);
        let post_quantum_signature: MlDsaSignature<MlDsa65> =
            post_quantum.try_sign(tbs.as_bytes()).unwrap();

        let signature = HybridSignature::try_new(
            profile,
            classical_signature.to_bytes().to_vec(),
            post_quantum_signature.encode().to_vec(),
        )
        .unwrap();
        let public_key = HybridPublicKey::try_new(
            profile,
            classical
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            post_quantum.verifying_key().encode().to_vec(),
        )
        .unwrap();
        VerificationFixture {
            signature_envelope: encode_signature(&HybridSignatureEnvelope::new(purpose, signature)),
            public_key_envelope: encode_public_key(&public_key),
            resolved: HybridKeyRef::try_new("wallet-key".into(), 7).unwrap(),
            expected: HybridKeyRef::try_new("wallet-key".into(), 7).unwrap(),
            context,
            payload,
        }
    }

    fn verification_fixture() -> VerificationFixture {
        verification_fixture_with(0x01)
    }

    #[test]
    fn ml_dsa_public_key_matches_the_cross_repo_anchor() {
        let seed_key = {
            let seed_bytes: Vec<u8> = (0_u8..32).collect();
            let seed = ml_dsa::Seed::try_from(&seed_bytes[..]).unwrap();
            ml_dsa::SigningKey::<MlDsa65>::from_seed(&seed)
        };
        let digest = Sha256::digest(seed_key.verifying_key().encode());
        let mut hex = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use core::fmt::Write;
            write!(&mut hex, "{byte:02x}").expect("String writes cannot fail");
        }
        assert_eq!(
            hex,
            "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9"
        );
    }

    #[test]
    fn valid_hybrid_signature_is_accepted_and_corruption_is_rejected() {
        let fixture = verification_fixture();
        verify_hybrid_signature_atomic(&fixture.input()).unwrap();

        for offset in [100_usize, fixture.signature_envelope.len() - 1] {
            let mut corrupted = verification_fixture();
            corrupted.signature_envelope[offset] ^= 1;
            let error = verify_hybrid_signature_atomic(&corrupted.input()).unwrap_err();
            assert_eq!(error.to_string(), "hybrid signature rejected");
            assert!(matches!(
                error.diagnostic_class(),
                HybridErrorClass::VerificationFailure | HybridErrorClass::NonCanonicalInput
            ));
        }
    }

    #[test]
    fn atomic_verifier_covers_the_complete_two_by_two_validity_matrix() {
        for (classical_valid, post_quantum_valid, accepted) in [
            (true, true, true),
            (false, true, false),
            (true, false, false),
            (false, false, false),
        ] {
            let mut fixture = verification_fixture();
            let envelope = decode_signature(&fixture.signature_envelope).unwrap();
            let mut classical = envelope.signature().classical().to_vec();
            let mut post_quantum = envelope.signature().post_quantum().to_vec();
            if !classical_valid {
                classical[0] ^= 1;
            }
            if !post_quantum_valid {
                post_quantum[0] ^= 1;
            }
            fixture.signature_envelope = encode_signature(&HybridSignatureEnvelope::new(
                envelope.purpose(),
                HybridSignature::try_new(
                    HybridSignatureProfile::Es256MlDsa65V1,
                    classical,
                    post_quantum,
                )
                .unwrap(),
            ));
            assert_eq!(
                verify_hybrid_signature_atomic(&fixture.input()).is_ok(),
                accepted,
                "classical_valid={classical_valid}, post_quantum_valid={post_quantum_valid}"
            );
        }
    }

    #[test]
    fn atomic_verifier_rejects_mixed_identity_generation_replay_time_and_downgrade() {
        let mut mixed_identity = verification_fixture();
        mixed_identity.expected = HybridKeyRef::try_new("other-wallet".into(), 7).unwrap();
        assert_eq!(
            verify_hybrid_signature_atomic(&mixed_identity.input())
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::Mismatch
        );

        let fixture = verification_fixture();
        let wrong_generation = HybridKeyRef::try_new("wallet-key".into(), 8).unwrap();
        let mut input = fixture.input();
        input.expected_key_ref = &wrong_generation;
        assert_eq!(
            verify_hybrid_signature_atomic(&input)
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::Mismatch
        );

        let seen = vec![fixture.context.nonce.clone()];
        let mut input = fixture.input();
        input.seen_nonces = &seen;
        assert_eq!(
            verify_hybrid_signature_atomic(&input)
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::PolicyDenied
        );

        let wrong_nonce = vec![9; 16];
        let mut input = fixture.input();
        input.expected_nonce = &wrong_nonce;
        assert_eq!(
            verify_hybrid_signature_atomic(&input)
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::PolicyDenied
        );

        let mut input = fixture.input();
        input.expected_audience = Some(b"unexpected-audience");
        assert_eq!(
            verify_hybrid_signature_atomic(&input)
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::PolicyDenied
        );

        let mut input = fixture.input();
        input.now_epoch_seconds = fixture.context.expires_at_epoch_seconds;
        assert_eq!(
            verify_hybrid_signature_atomic(&input)
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::PolicyDenied
        );

        let mut input = fixture.input();
        input.downgrade_attempted = true;
        assert_eq!(
            verify_hybrid_signature_atomic(&input)
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::DowngradeDetected
        );
    }

    #[test]
    fn atomic_verifier_rejects_missing_unsupported_and_cross_key_components() {
        let mut truncated = verification_fixture();
        truncated.signature_envelope.truncate(40);
        assert_eq!(
            verify_hybrid_signature_atomic(&truncated.input())
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::NonCanonicalInput
        );

        let mut unsupported = verification_fixture();
        let profile = b"euwallet-hybrid-pq-v1";
        let offset = unsupported
            .signature_envelope
            .windows(profile.len())
            .position(|window| window == profile)
            .unwrap();
        unsupported.signature_envelope[offset + profile.len() - 1] = b'2';
        assert_eq!(
            verify_hybrid_signature_atomic(&unsupported.input())
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::UnsupportedProfile
        );

        let mut first = verification_fixture_with(0x01);
        let second = verification_fixture_with(0x02);
        let first_signature = decode_signature(&first.signature_envelope).unwrap();
        let second_signature = decode_signature(&second.signature_envelope).unwrap();
        let mixed = HybridSignature::try_new(
            HybridSignatureProfile::Es256MlDsa65V1,
            first_signature.signature().classical().to_vec(),
            second_signature.signature().post_quantum().to_vec(),
        )
        .unwrap();
        first.signature_envelope = encode_signature(&HybridSignatureEnvelope::new(
            HybridPurpose::WalletExportV1,
            mixed,
        ));
        assert_eq!(
            verify_hybrid_signature_atomic(&first.input())
                .unwrap_err()
                .diagnostic_class(),
            HybridErrorClass::VerificationFailure
        );
    }

    #[test]
    fn trait_verifier_is_atomic_over_one_tbs() {
        let profile = HybridSignatureProfile::Es256MlDsa65V1;
        let purpose = HybridPurpose::WalletExportV1;
        let context = HybridContext {
            wallet_identity: b"wallet-key".to_vec(),
            issuer_identity: None,
            key_generation: 7,
            transaction_id: None,
            session_id: None,
            audience: None,
            nonce: (0_u8..16).collect(),
            created_at_epoch_seconds: 1_700_000_000,
            expires_at_epoch_seconds: 1_700_000_100,
            transcript_hash: None,
        };
        let tbs = HybridTbs::build(profile, purpose, &context, b"payload").unwrap();

        let classical = EcdsaSigningKey::from_slice(&[0x03; 32]).unwrap();
        let classical_signature: EcdsaSignature = classical.sign(tbs.as_bytes());
        let post_quantum = ml_dsa_signing_key(0x03);
        let post_quantum_signature: MlDsaSignature<MlDsa65> =
            post_quantum.try_sign(tbs.as_bytes()).unwrap();

        let key = HybridPublicKey::try_new(
            profile,
            classical
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            post_quantum.verifying_key().encode().to_vec(),
        )
        .unwrap();
        let signature = HybridSignature::try_new(
            profile,
            classical_signature.to_bytes().to_vec(),
            post_quantum_signature.encode().to_vec(),
        )
        .unwrap();

        RustCryptoHybridVerifier
            .verify_hybrid(&key, &tbs, &signature)
            .unwrap();

        let mut broken_classical = signature.classical().to_vec();
        broken_classical[0] ^= 1;
        let broken =
            HybridSignature::try_new(profile, broken_classical, signature.post_quantum().to_vec())
                .unwrap();
        assert_eq!(
            RustCryptoHybridVerifier.verify_hybrid(&key, &tbs, &broken),
            Err(HybridCryptoError::VerificationFailure {
                component: HybridComponent::Classical
            })
        );
    }
}
