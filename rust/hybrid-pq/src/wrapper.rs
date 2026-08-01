//! Frozen `HybridCredentialWrapperV1` container for `euwallet-hybrid-pq-v1`.
//!
//! The wrapper carries an experimental credential payload, its disclosures, both
//! component key identifiers, the logical key generation, and both mandatory
//! signatures in one strict deterministic-CBOR map behind the shared magic
//! prefix. Key identifiers and the generation field are not signed; verifiers
//! must bind them to the trusted logical identity and to the context
//! `key_generation`. The signed TBS payload component is the committed map
//! `{1: payload, 2: [disclosures]}` fed to the frozen `HybridTbsV1`
//! construction.

use crate::envelope::{
    Decoder, EnvelopeError, MAGIC_PREFIX, write_bytes_pair, write_head, write_text_pair,
    write_uint_pair,
};
use crate::tbs::{HybridContext, HybridPurpose, HybridTbs};
use crate::{
    ES256_SIGNATURE_BYTES, HybridCryptoError, HybridMismatch, HybridPublicKey, HybridSignature,
    HybridSignatureProfile, HybridVerifier, ML_DSA_65_SIGNATURE_BYTES,
};

pub const WRAPPER_VERSION: u64 = 1;
pub const CREDENTIAL_FORMAT: &str = "dev-hybrid-pq+cbor";
pub const MAX_WRAPPER_BYTES: usize = 64 * 1024;
pub const MAX_PAYLOAD_BYTES: usize = 4_096;
pub const MAX_COMMITTED_PAYLOAD_BYTES: usize = 4_096;
pub const MAX_KEY_ID_BYTES: usize = 128;

const KEY_VERSION: u64 = 1;
const KEY_PROFILE: u64 = 2;
const KEY_PURPOSE: u64 = 3;
const KEY_FORMAT: u64 = 4;
const KEY_PAYLOAD: u64 = 5;
const KEY_DISCLOSURES: u64 = 6;
const KEY_CLASSICAL_KEY_ID: u64 = 7;
const KEY_PQ_KEY_ID: u64 = 8;
const KEY_GENERATION: u64 = 9;
const KEY_CLASSICAL_SIGNATURE: u64 = 10;
const KEY_POST_QUANTUM_SIGNATURE: u64 = 11;
const WRAPPER_FIELDS: u64 = 11;

/// One frozen experimental credential wrapper. Construction enforces every
/// bound the decoder enforces, so encode/decode round trips are byte-stable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HybridCredentialWrapper {
    purpose: HybridPurpose,
    payload: Vec<u8>,
    disclosures: Vec<Vec<u8>>,
    classical_key_id: String,
    pq_key_id: String,
    generation: u64,
    signature: HybridSignature,
}

/// Unsigned key-binding expectations a verifier must supply from trusted state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrapperBinding {
    pub classical_key_id: String,
    pub pq_key_id: String,
    pub generation: u64,
}

impl HybridCredentialWrapper {
    /// Construct a wrapper while enforcing the frozen profile bounds.
    ///
    /// # Errors
    ///
    /// Rejects unsupported purposes, empty or oversized payload fields, invalid key identifiers,
    /// zero generations, and committed payloads exceeding the frozen limit.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        purpose: HybridPurpose,
        payload: Vec<u8>,
        disclosures: Vec<Vec<u8>>,
        classical_key_id: String,
        pq_key_id: String,
        generation: u64,
        signature: HybridSignature,
    ) -> Result<Self, HybridCryptoError> {
        if !is_wrapper_purpose(purpose) {
            return Err(HybridCryptoError::PolicyDenied);
        }
        if payload.is_empty() {
            return Err(HybridCryptoError::NonCanonicalInput);
        }
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(HybridCryptoError::ResourceLimitExceeded);
        }
        for disclosure in &disclosures {
            if disclosure.is_empty() {
                return Err(HybridCryptoError::NonCanonicalInput);
            }
            if disclosure.len() > MAX_PAYLOAD_BYTES {
                return Err(HybridCryptoError::ResourceLimitExceeded);
            }
        }
        validate_key_id(&classical_key_id)?;
        validate_key_id(&pq_key_id)?;
        if generation == 0 {
            return Err(HybridCryptoError::Mismatch {
                field: HybridMismatch::Generation,
            });
        }
        if committed_payload(&payload, &disclosures).len() > MAX_COMMITTED_PAYLOAD_BYTES {
            return Err(HybridCryptoError::ResourceLimitExceeded);
        }
        Ok(Self {
            purpose,
            payload,
            disclosures,
            classical_key_id,
            pq_key_id,
            generation,
            signature,
        })
    }

    #[must_use]
    pub fn purpose(&self) -> HybridPurpose {
        self.purpose
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub fn disclosures(&self) -> &[Vec<u8>] {
        &self.disclosures
    }

    #[must_use]
    pub fn classical_key_id(&self) -> &str {
        &self.classical_key_id
    }

    #[must_use]
    pub fn pq_key_id(&self) -> &str {
        &self.pq_key_id
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub fn signature(&self) -> &HybridSignature {
        &self.signature
    }

    /// The exact bytes both component signatures must cover.
    ///
    /// # Errors
    ///
    /// Rejects any context or committed payload that violates the frozen TBS profile.
    pub fn tbs(&self, context: &HybridContext) -> Result<HybridTbs, HybridCryptoError> {
        HybridTbs::build(
            self.signature.profile(),
            self.purpose,
            context,
            &committed_payload(&self.payload, &self.disclosures),
        )
    }
}

/// The committed canonical-CBOR payload map `{1: payload, 2: [disclosures]}`
/// bound into the TBS, so disclosure mutation fails closed.
pub fn committed_payload(payload: &[u8], disclosures: &[Vec<u8>]) -> Vec<u8> {
    let mut output =
        Vec::with_capacity(payload.len() + disclosures.iter().map(Vec::len).sum::<usize>() + 32);
    write_head(&mut output, 5, 2);
    write_bytes_pair(&mut output, 1, payload);
    write_head(&mut output, 0, 2);
    write_head(&mut output, 4, disclosures.len() as u64);
    for disclosure in disclosures {
        write_head(&mut output, 2, disclosure.len() as u64);
        output.extend_from_slice(disclosure);
    }
    output
}

#[must_use]
pub fn encode_credential_wrapper(wrapper: &HybridCredentialWrapper) -> Vec<u8> {
    let signature = wrapper.signature();
    let mut output = Vec::with_capacity(
        MAGIC_PREFIX.len()
            + wrapper.payload().len()
            + signature.classical().len()
            + signature.post_quantum().len()
            + 256,
    );
    output.extend_from_slice(MAGIC_PREFIX);
    write_head(&mut output, 5, WRAPPER_FIELDS);
    write_uint_pair(&mut output, KEY_VERSION, WRAPPER_VERSION);
    write_text_pair(&mut output, KEY_PROFILE, signature.profile().id());
    write_text_pair(&mut output, KEY_PURPOSE, wrapper.purpose().id());
    write_text_pair(&mut output, KEY_FORMAT, CREDENTIAL_FORMAT);
    write_bytes_pair(&mut output, KEY_PAYLOAD, wrapper.payload());
    write_head(&mut output, 0, KEY_DISCLOSURES);
    write_head(&mut output, 4, wrapper.disclosures().len() as u64);
    for disclosure in wrapper.disclosures() {
        write_head(&mut output, 2, disclosure.len() as u64);
        output.extend_from_slice(disclosure);
    }
    write_text_pair(
        &mut output,
        KEY_CLASSICAL_KEY_ID,
        wrapper.classical_key_id(),
    );
    write_text_pair(&mut output, KEY_PQ_KEY_ID, wrapper.pq_key_id());
    write_uint_pair(&mut output, KEY_GENERATION, wrapper.generation());
    write_bytes_pair(&mut output, KEY_CLASSICAL_SIGNATURE, signature.classical());
    write_bytes_pair(
        &mut output,
        KEY_POST_QUANTUM_SIGNATURE,
        signature.post_quantum(),
    );
    output
}

/// Decode the strict deterministic-CBOR credential wrapper.
///
/// # Errors
///
/// Rejects every malformed, non-canonical, oversized, incomplete, or unsupported wrapper.
#[allow(clippy::too_many_lines)]
pub fn decode_credential_wrapper(input: &[u8]) -> Result<HybridCredentialWrapper, EnvelopeError> {
    if input.len() > MAX_WRAPPER_BYTES {
        return Err(EnvelopeError::TooLarge);
    }
    let cbor = input
        .strip_prefix(MAGIC_PREFIX)
        .ok_or(EnvelopeError::BadPrefix)?;
    let mut decoder = Decoder::new(cbor);
    let (major, entries) = decoder.read_head()?;
    if major != 5 {
        return Err(EnvelopeError::WrongType);
    }

    let mut previous_key = None;
    let mut version = None;
    let mut profile = None;
    let mut purpose = None;
    let mut format_seen = false;
    let mut payload = None;
    let mut disclosures = None;
    let mut classical_key_id = None;
    let mut pq_key_id = None;
    let mut generation = None;
    let mut classical_signature = None;
    let mut post_quantum_signature = None;

    for _ in 0..entries {
        let key = decoder.read_uint()?;
        if let Some(previous) = previous_key {
            if key == previous {
                return Err(EnvelopeError::DuplicateKey);
            }
            if key < previous {
                return Err(EnvelopeError::MapKeysNotSorted);
            }
        }
        previous_key = Some(key);
        match key {
            KEY_VERSION => version = Some(decoder.read_uint()?),
            KEY_PROFILE => {
                let value = decoder.read_text()?;
                profile = Some(
                    HybridSignatureProfile::try_from(value)
                        .map_err(|_| EnvelopeError::UnsupportedProfile)?,
                );
            }
            KEY_PURPOSE => {
                let value = decoder.read_text()?;
                let parsed = HybridPurpose::try_from(value)
                    .map_err(|_| EnvelopeError::UnsupportedPurpose)?;
                if !is_wrapper_purpose(parsed) {
                    return Err(EnvelopeError::UnsupportedPurpose);
                }
                purpose = Some(parsed);
            }
            KEY_FORMAT => {
                if decoder.read_text()? != CREDENTIAL_FORMAT {
                    return Err(EnvelopeError::UnsupportedFormat);
                }
                format_seen = true;
            }
            KEY_PAYLOAD => {
                let value = decoder.read_string(2, MAX_PAYLOAD_BYTES)?;
                if value.is_empty() {
                    return Err(EnvelopeError::EmptyField);
                }
                payload = Some(value.to_vec());
            }
            KEY_DISCLOSURES => {
                let (major, count) = decoder.read_head()?;
                if major != 4 {
                    return Err(EnvelopeError::WrongType);
                }
                let mut entries = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
                for _ in 0..count {
                    let value = decoder.read_string(2, MAX_PAYLOAD_BYTES)?;
                    if value.is_empty() {
                        return Err(EnvelopeError::EmptyField);
                    }
                    entries.push(value.to_vec());
                }
                disclosures = Some(entries);
            }
            KEY_CLASSICAL_KEY_ID => classical_key_id = Some(read_key_id(&mut decoder)?),
            KEY_PQ_KEY_ID => pq_key_id = Some(read_key_id(&mut decoder)?),
            KEY_GENERATION => {
                let value = decoder.read_uint()?;
                if value == 0 {
                    return Err(EnvelopeError::ZeroGeneration);
                }
                generation = Some(value);
            }
            KEY_CLASSICAL_SIGNATURE => {
                classical_signature = Some(decoder.read_string(2, ES256_SIGNATURE_BYTES)?.to_vec());
            }
            KEY_POST_QUANTUM_SIGNATURE => {
                post_quantum_signature =
                    Some(decoder.read_string(2, ML_DSA_65_SIGNATURE_BYTES)?.to_vec());
            }
            _ => return Err(EnvelopeError::UnknownField),
        }
    }
    if !decoder.is_finished() {
        return Err(EnvelopeError::TrailingBytes);
    }
    if version.ok_or(EnvelopeError::MissingField)? != WRAPPER_VERSION {
        return Err(EnvelopeError::UnsupportedVersion);
    }
    if !format_seen {
        return Err(EnvelopeError::MissingField);
    }
    let profile = profile.ok_or(EnvelopeError::MissingField)?;
    let signature = HybridSignature::try_new(
        profile,
        classical_signature.ok_or(EnvelopeError::MissingField)?,
        post_quantum_signature.ok_or(EnvelopeError::MissingField)?,
    )
    .map_err(|_| EnvelopeError::MalformedComponent)?;
    HybridCredentialWrapper::try_new(
        purpose.ok_or(EnvelopeError::MissingField)?,
        payload.ok_or(EnvelopeError::MissingField)?,
        disclosures.ok_or(EnvelopeError::MissingField)?,
        classical_key_id.ok_or(EnvelopeError::MissingField)?,
        pq_key_id.ok_or(EnvelopeError::MissingField)?,
        generation.ok_or(EnvelopeError::MissingField)?,
        signature,
    )
    .map_err(|error| match error {
        HybridCryptoError::ResourceLimitExceeded => EnvelopeError::TooLarge,
        _ => EnvelopeError::MalformedComponent,
    })
}

/// Atomically verify one decoded wrapper: bind the unsigned key identifiers and
/// generation to trusted expectations and the context, rebuild the committed
/// TBS, and require both component signatures over the identical bytes.
///
/// # Errors
///
/// Rejects purpose, trusted key binding, generation, context, profile, or either signature
/// mismatch. No partial component-success result is returned.
pub fn verify_credential_wrapper<V: HybridVerifier>(
    wrapper: &HybridCredentialWrapper,
    expected_purpose: HybridPurpose,
    binding: &WrapperBinding,
    context: &HybridContext,
    public_key: &HybridPublicKey,
    verifier: &V,
) -> Result<(), HybridCryptoError> {
    if wrapper.purpose() != expected_purpose {
        return Err(HybridCryptoError::PolicyDenied);
    }
    if wrapper.classical_key_id() != binding.classical_key_id
        || wrapper.pq_key_id() != binding.pq_key_id
    {
        return Err(HybridCryptoError::Mismatch {
            field: HybridMismatch::Identity,
        });
    }
    if wrapper.generation() != binding.generation || context.key_generation != binding.generation {
        return Err(HybridCryptoError::Mismatch {
            field: HybridMismatch::Generation,
        });
    }
    let tbs = wrapper.tbs(context)?;
    verifier.verify_hybrid(public_key, &tbs, wrapper.signature())
}

fn is_wrapper_purpose(purpose: HybridPurpose) -> bool {
    matches!(
        purpose,
        HybridPurpose::TestSdJwtWrapperV1 | HybridPurpose::TestMdocWrapperV1
    )
}

fn validate_key_id(value: &str) -> Result<(), HybridCryptoError> {
    if value.is_empty() {
        return Err(HybridCryptoError::NonCanonicalInput);
    }
    if value.len() > MAX_KEY_ID_BYTES {
        return Err(HybridCryptoError::ResourceLimitExceeded);
    }
    Ok(())
}

fn read_key_id(decoder: &mut Decoder<'_>) -> Result<String, EnvelopeError> {
    let bytes = decoder.read_string(3, MAX_KEY_ID_BYTES)?;
    if bytes.is_empty() {
        return Err(EnvelopeError::EmptyField);
    }
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| EnvelopeError::InvalidUtf8)
}
