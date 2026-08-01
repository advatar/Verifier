#![forbid(unsafe_code)]
//! Verifier-side types for the isolated `euwallet-hybrid-pq-v1` experiment.
//!
//! Ported from the `../EUWallet` `hybrid-pq` crate. This crate deliberately
//! does not extend any certified algorithm registry, implement JOSE/COSE
//! conversions, or provide cryptographic primitives. Hybrid artifacts are
//! structurally disjoint from every production credential encoding: they carry
//! a mandatory magic prefix and their profile identifiers are distinct Rust
//! types that cannot flow into certified algorithm parameters.
//!
//! Acceptance is atomic: a hybrid signature validates only when both the ES256
//! and ML-DSA-65 components verify over the identical domain-separated bytes.
//! There is no classical-only or post-quantum-only success state.

use std::fmt;

pub mod envelope;
pub mod tbs;
pub mod wrapper;

/// Exact public component sizes frozen by `euwallet-hybrid-pq-v1`.
pub const ES256_PUBLIC_KEY_BYTES: usize = 65;
pub const ES256_SIGNATURE_BYTES: usize = 64;
pub const ML_DSA_65_PUBLIC_KEY_BYTES: usize = 1_952;
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3_309;

/// Closed experimental signature-profile registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HybridSignatureProfile {
    Es256MlDsa65V1,
}

impl HybridSignatureProfile {
    pub const ID: &'static str = "euwallet-hybrid-pq-v1";

    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Es256MlDsa65V1 => Self::ID,
        }
    }
}

impl TryFrom<&str> for HybridSignatureProfile {
    type Error = HybridCryptoError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            Self::ID => Ok(Self::Es256MlDsa65V1),
            _ => Err(HybridCryptoError::UnsupportedProfile),
        }
    }
}

/// One half of a hybrid construction, used in non-secret failure classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HybridComponent {
    Classical,
    PostQuantum,
}

/// Fields that must agree across both component keys and the selected operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HybridMismatch {
    Profile,
    Identity,
    Generation,
}

/// Stable error classes exposed by the experimental trait boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HybridErrorClass {
    UnsupportedProfile,
    MalformedComponent,
    ComponentFailure,
    VerificationFailure,
    Mismatch,
    NonCanonicalInput,
    ResourceLimitExceeded,
    DowngradeDetected,
    PolicyDenied,
    BackendFailure,
}

/// Typed, deliberately low-detail failures. Backends must not attach key
/// material, payloads or decapsulation-oracle detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HybridCryptoError {
    UnsupportedProfile,
    MalformedComponent { component: HybridComponent },
    ComponentFailure { component: HybridComponent },
    VerificationFailure { component: HybridComponent },
    Mismatch { field: HybridMismatch },
    NonCanonicalInput,
    ResourceLimitExceeded,
    DowngradeDetected,
    PolicyDenied,
    BackendFailure,
}

impl HybridCryptoError {
    #[must_use]
    pub fn class(&self) -> HybridErrorClass {
        match self {
            Self::UnsupportedProfile => HybridErrorClass::UnsupportedProfile,
            Self::MalformedComponent { .. } => HybridErrorClass::MalformedComponent,
            Self::ComponentFailure { .. } => HybridErrorClass::ComponentFailure,
            Self::VerificationFailure { .. } => HybridErrorClass::VerificationFailure,
            Self::Mismatch { .. } => HybridErrorClass::Mismatch,
            Self::NonCanonicalInput => HybridErrorClass::NonCanonicalInput,
            Self::ResourceLimitExceeded => HybridErrorClass::ResourceLimitExceeded,
            Self::DowngradeDetected => HybridErrorClass::DowngradeDetected,
            Self::PolicyDenied => HybridErrorClass::PolicyDenied,
            Self::BackendFailure => HybridErrorClass::BackendFailure,
        }
    }
}

impl fmt::Display for HybridCryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.class() {
            HybridErrorClass::UnsupportedProfile => "unsupported hybrid profile",
            HybridErrorClass::MalformedComponent => "malformed hybrid component",
            HybridErrorClass::ComponentFailure => "hybrid component operation failed",
            HybridErrorClass::VerificationFailure => "hybrid verification failed",
            HybridErrorClass::Mismatch => "hybrid key binding mismatch",
            HybridErrorClass::NonCanonicalInput => "non-canonical hybrid input",
            HybridErrorClass::ResourceLimitExceeded => "hybrid resource limit exceeded",
            HybridErrorClass::DowngradeDetected => "hybrid downgrade detected",
            HybridErrorClass::PolicyDenied => "hybrid operation denied by policy",
            HybridErrorClass::BackendFailure => "hybrid backend failure",
        })
    }
}

impl std::error::Error for HybridCryptoError {}

/// Public keys forming one atomic hybrid verification identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridPublicKey {
    profile: HybridSignatureProfile,
    classical: Vec<u8>,
    post_quantum: Vec<u8>,
}

impl HybridPublicKey {
    /// # Errors
    ///
    /// Fails when either component has a non-frozen size or the classical key
    /// is not an uncompressed SEC1 point.
    pub fn try_new(
        profile: HybridSignatureProfile,
        classical: Vec<u8>,
        post_quantum: Vec<u8>,
    ) -> Result<Self, HybridCryptoError> {
        require_len(
            &classical,
            ES256_PUBLIC_KEY_BYTES,
            HybridComponent::Classical,
        )?;
        if classical[0] != 0x04 {
            return Err(HybridCryptoError::MalformedComponent {
                component: HybridComponent::Classical,
            });
        }
        require_len(
            &post_quantum,
            ML_DSA_65_PUBLIC_KEY_BYTES,
            HybridComponent::PostQuantum,
        )?;
        Ok(Self {
            profile,
            classical,
            post_quantum,
        })
    }

    #[must_use]
    pub fn profile(&self) -> HybridSignatureProfile {
        self.profile
    }

    #[must_use]
    pub fn classical(&self) -> &[u8] {
        &self.classical
    }

    #[must_use]
    pub fn post_quantum(&self) -> &[u8] {
        &self.post_quantum
    }
}

/// Both mandatory signatures over one common domain-separated message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridSignature {
    profile: HybridSignatureProfile,
    classical: Vec<u8>,
    post_quantum: Vec<u8>,
}

impl HybridSignature {
    /// # Errors
    ///
    /// Fails when either component has a non-frozen size.
    pub fn try_new(
        profile: HybridSignatureProfile,
        classical: Vec<u8>,
        post_quantum: Vec<u8>,
    ) -> Result<Self, HybridCryptoError> {
        require_len(
            &classical,
            ES256_SIGNATURE_BYTES,
            HybridComponent::Classical,
        )?;
        require_len(
            &post_quantum,
            ML_DSA_65_SIGNATURE_BYTES,
            HybridComponent::PostQuantum,
        )?;
        Ok(Self {
            profile,
            classical,
            post_quantum,
        })
    }

    #[must_use]
    pub fn profile(&self) -> HybridSignatureProfile {
        self.profile
    }

    #[must_use]
    pub fn classical(&self) -> &[u8] {
        &self.classical
    }

    #[must_use]
    pub fn post_quantum(&self) -> &[u8] {
        &self.post_quantum
    }
}

/// Opaque reference to two component keys bound to one logical identity and generation.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HybridKeyRef {
    identity: String,
    generation: u64,
}

impl HybridKeyRef {
    pub const MAX_IDENTITY_BYTES: usize = 128;

    /// # Errors
    ///
    /// Fails on an empty or oversized identity or a zero generation.
    pub fn try_new(identity: String, generation: u64) -> Result<Self, HybridCryptoError> {
        if identity.is_empty() {
            return Err(HybridCryptoError::MalformedComponent {
                component: HybridComponent::Classical,
            });
        }
        if identity.len() > Self::MAX_IDENTITY_BYTES {
            return Err(HybridCryptoError::ResourceLimitExceeded);
        }
        if generation == 0 {
            return Err(HybridCryptoError::Mismatch {
                field: HybridMismatch::Generation,
            });
        }
        Ok(Self {
            identity,
            generation,
        })
    }

    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// Verify both mandatory components against the same caller-supplied bytes.
pub trait HybridVerifier {
    /// # Errors
    ///
    /// Fails closed unless both the classical and post-quantum components
    /// verify over the identical [`tbs::HybridTbs`] bytes.
    fn verify_hybrid(
        &self,
        key: &HybridPublicKey,
        hybrid_tbs: &tbs::HybridTbs,
        signature: &HybridSignature,
    ) -> Result<(), HybridCryptoError>;
}

fn require_len(
    value: &[u8],
    expected: usize,
    component: HybridComponent,
) -> Result<(), HybridCryptoError> {
    if value.len() != expected {
        return Err(HybridCryptoError::MalformedComponent { component });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classical_public_key() -> Vec<u8> {
        let mut key = vec![0; ES256_PUBLIC_KEY_BYTES];
        key[0] = 0x04;
        key
    }

    #[test]
    fn parses_only_the_frozen_profile() {
        assert_eq!(
            HybridSignatureProfile::try_from("euwallet-hybrid-pq-v1"),
            Ok(HybridSignatureProfile::Es256MlDsa65V1)
        );
        assert_eq!(
            HybridSignatureProfile::try_from("euwallet-hybrid-pq-v2"),
            Err(HybridCryptoError::UnsupportedProfile)
        );
    }

    #[test]
    fn public_key_requires_both_exact_components() {
        let valid = HybridPublicKey::try_new(
            HybridSignatureProfile::Es256MlDsa65V1,
            classical_public_key(),
            vec![0; ML_DSA_65_PUBLIC_KEY_BYTES],
        )
        .expect("valid fixed-size components");
        assert_eq!(valid.classical().len(), ES256_PUBLIC_KEY_BYTES);
        assert_eq!(valid.post_quantum().len(), ML_DSA_65_PUBLIC_KEY_BYTES);

        assert_eq!(
            HybridPublicKey::try_new(
                HybridSignatureProfile::Es256MlDsa65V1,
                vec![0; ES256_PUBLIC_KEY_BYTES],
                vec![0; ML_DSA_65_PUBLIC_KEY_BYTES],
            ),
            Err(HybridCryptoError::MalformedComponent {
                component: HybridComponent::Classical
            })
        );
        assert_eq!(
            HybridPublicKey::try_new(
                HybridSignatureProfile::Es256MlDsa65V1,
                classical_public_key(),
                vec![],
            ),
            Err(HybridCryptoError::MalformedComponent {
                component: HybridComponent::PostQuantum
            })
        );
    }

    #[test]
    fn signature_requires_both_exact_components() {
        let valid = HybridSignature::try_new(
            HybridSignatureProfile::Es256MlDsa65V1,
            vec![0; ES256_SIGNATURE_BYTES],
            vec![0; ML_DSA_65_SIGNATURE_BYTES],
        )
        .expect("valid fixed-size components");
        assert_eq!(valid.classical().len(), ES256_SIGNATURE_BYTES);
        assert_eq!(valid.post_quantum().len(), ML_DSA_65_SIGNATURE_BYTES);

        assert_eq!(
            HybridSignature::try_new(
                HybridSignatureProfile::Es256MlDsa65V1,
                vec![],
                vec![0; ML_DSA_65_SIGNATURE_BYTES],
            ),
            Err(HybridCryptoError::MalformedComponent {
                component: HybridComponent::Classical
            })
        );
    }

    #[test]
    fn key_reference_binds_identity_and_nonzero_generation() {
        let key = HybridKeyRef::try_new("wallet-key".into(), 7).expect("valid key reference");
        assert_eq!(key.identity(), "wallet-key");
        assert_eq!(key.generation(), 7);
        assert_eq!(
            HybridKeyRef::try_new("wallet-key".into(), 0),
            Err(HybridCryptoError::Mismatch {
                field: HybridMismatch::Generation
            })
        );
        assert_eq!(
            HybridKeyRef::try_new("x".repeat(HybridKeyRef::MAX_IDENTITY_BYTES + 1), 1),
            Err(HybridCryptoError::ResourceLimitExceeded)
        );
    }

    #[test]
    fn every_error_class_is_typed_and_stable() {
        let cases = [
            (
                HybridCryptoError::UnsupportedProfile,
                HybridErrorClass::UnsupportedProfile,
            ),
            (
                HybridCryptoError::MalformedComponent {
                    component: HybridComponent::Classical,
                },
                HybridErrorClass::MalformedComponent,
            ),
            (
                HybridCryptoError::ComponentFailure {
                    component: HybridComponent::PostQuantum,
                },
                HybridErrorClass::ComponentFailure,
            ),
            (
                HybridCryptoError::VerificationFailure {
                    component: HybridComponent::Classical,
                },
                HybridErrorClass::VerificationFailure,
            ),
            (
                HybridCryptoError::Mismatch {
                    field: HybridMismatch::Identity,
                },
                HybridErrorClass::Mismatch,
            ),
            (
                HybridCryptoError::NonCanonicalInput,
                HybridErrorClass::NonCanonicalInput,
            ),
            (
                HybridCryptoError::ResourceLimitExceeded,
                HybridErrorClass::ResourceLimitExceeded,
            ),
            (
                HybridCryptoError::DowngradeDetected,
                HybridErrorClass::DowngradeDetected,
            ),
            (
                HybridCryptoError::PolicyDenied,
                HybridErrorClass::PolicyDenied,
            ),
            (
                HybridCryptoError::BackendFailure,
                HybridErrorClass::BackendFailure,
            ),
        ];

        for (error, class) in cases {
            assert_eq!(error.class(), class);
            assert!(!error.to_string().is_empty());
        }
    }
}
