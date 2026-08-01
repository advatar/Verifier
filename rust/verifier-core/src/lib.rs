#![forbid(unsafe_code)]
#![no_std]
//! Pure authorization kernel for an EUDI Wallet relying party.
//!
//! Parsing, certificate path validation, signature verification, status-list
//! retrieval, and HTTP transport belong in audited adapters. Those adapters
//! produce the structured evidence consumed here. Only a successful
//! [`authorize_accept`] decision may release verified attributes.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant(pub u64);

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub u128);
    };
}

id_type!(SessionId);
id_type!(RequestId);
id_type!(ResponseId);
id_type!(ClientId);
id_type!(NonceId);
id_type!(TranscriptHash);
id_type!(CredentialTypeId);
id_type!(IssuerId);
id_type!(TrustAnchorId);
id_type!(HolderKeyId);
id_type!(SubjectId);
id_type!(DisclosureSetId);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialFormat {
    SdJwtVc,
    Mdoc,
}

const fn same_format(left: CredentialFormat, right: CredentialFormat) -> bool {
    matches!(
        (left, right),
        (CredentialFormat::SdJwtVc, CredentialFormat::SdJwtVc)
            | (CredentialFormat::Mdoc, CredentialFormat::Mdoc)
    )
}

/// Signature suite proved by the cryptographic adapter for one credential.
///
/// `HybridPqV1` records that an adapter verified the isolated
/// `euwallet-hybrid-pq-v1` profile: both the ES256 and ML-DSA-65 components
/// over identical domain-separated bytes, atomically. A policy that requires
/// the hybrid suite can never be satisfied by classical-only evidence, so a
/// downgrade is rejected before signature freshness is even considered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureSuite {
    Classical,
    HybridPqV1,
}

const fn same_suite(left: SignatureSuite, right: SignatureSuite) -> bool {
    matches!(
        (left, right),
        (SignatureSuite::Classical, SignatureSuite::Classical)
            | (SignatureSuite::HybridPqV1, SignatureSuite::HybridPqV1)
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimedEvidence {
    pub valid_from: Instant,
    pub valid_until: Instant,
    pub checked_at: Instant,
    pub accepted: bool,
}

impl TimedEvidence {
    /// Evidence is fail-closed and cannot be used outside its asserted interval
    /// or after the policy's maximum evidence age.
    #[must_use]
    pub const fn usable_at(self, now: Instant, max_age: u64) -> bool {
        self.accepted
            && self.valid_from.0 <= now.0
            && now.0 < self.valid_until.0
            && self.checked_at.0 <= now.0
            && now.0 - self.checked_at.0 <= max_age
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationPolicy {
    pub credential_type: CredentialTypeId,
    pub format: CredentialFormat,
    pub required_disclosures: DisclosureSetId,
    pub allowed_trust_anchor: TrustAnchorId,
    pub required_signature_suite: SignatureSuite,
    pub require_holder_binding: bool,
    pub require_same_subject: bool,
    pub max_clock_skew: u64,
    pub max_status_age: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PresentationRequest {
    pub id: RequestId,
    pub client_id: ClientId,
    pub nonce: NonceId,
    pub transcript: TranscriptHash,
    pub issued_at: Instant,
    pub expires_at: Instant,
    pub policy: VerificationPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialEvidence {
    pub format: CredentialFormat,
    pub credential_type: CredentialTypeId,
    pub issuer: IssuerId,
    pub trust_anchor: TrustAnchorId,
    pub subject: SubjectId,
    pub holder_key: HolderKeyId,
    pub disclosures: DisclosureSetId,
    pub signature_suite: SignatureSuite,
    pub signature: TimedEvidence,
    pub status: TimedEvidence,
    pub not_revoked: bool,
    pub claims_well_formed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// Each flag records a distinct adapter proof obligation; merging them would
// erase the gate-to-requirement traceability used by the formal model.
#[allow(clippy::struct_excessive_bools)]
pub struct PresentationEvidence {
    pub response_id: ResponseId,
    pub request_id: RequestId,
    pub client_id: ClientId,
    pub nonce: NonceId,
    pub transcript: TranscriptHash,
    pub audience_verified: bool,
    pub response_integrity_verified: bool,
    pub holder_binding_verified: bool,
    pub holder_key: HolderKeyId,
    pub credential_count: u16,
    pub credentials_share_subject: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationSession {
    pub id: SessionId,
    pub request: PresentationRequest,
    pub request_authenticated: bool,
    pub response_unused: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptCommand {
    pub session_id: SessionId,
    pub response_id: ResponseId,
    pub credential_type: CredentialTypeId,
    pub issuer: IssuerId,
    pub subject: SubjectId,
    pub disclosures: DisclosureSetId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationError {
    RequestNotAuthenticated,
    RequestNotCurrent,
    RequestBindingMismatch,
    ResponseReplay,
    ResponseIntegrityInvalid,
    AudienceInvalid,
    CredentialCountInvalid,
    FormatNotAllowed,
    CredentialTypeNotAllowed,
    IssuerNotTrusted,
    SignatureSuiteNotAllowed,
    SignatureInvalid,
    StatusInvalid,
    CredentialRevoked,
    ClaimsInvalid,
    DisclosurePolicyNotSatisfied,
    HolderBindingInvalid,
    SubjectBindingInvalid,
}

/// Total, ordered, fail-closed implementation of the canonical `MayAccept`
/// predicate. Equality of `DisclosureSetId` means an adapter has proved the
/// exact policy-selected disclosure set, avoiding accidental over-disclosure.
///
/// # Errors
///
/// Returns the first failed verification gate. No attributes are released.
pub const fn authorize_accept(
    session: VerificationSession,
    presentation: PresentationEvidence,
    credential: CredentialEvidence,
    now: Instant,
) -> Result<AcceptCommand, VerificationError> {
    let request = session.request;
    let policy = request.policy;

    if !session.request_authenticated {
        return Err(VerificationError::RequestNotAuthenticated);
    }
    if now.0.saturating_add(policy.max_clock_skew) < request.issued_at.0
        || now.0 >= request.expires_at.0.saturating_add(policy.max_clock_skew)
    {
        return Err(VerificationError::RequestNotCurrent);
    }
    if presentation.request_id.0 != request.id.0
        || presentation.client_id.0 != request.client_id.0
        || presentation.nonce.0 != request.nonce.0
        || presentation.transcript.0 != request.transcript.0
    {
        return Err(VerificationError::RequestBindingMismatch);
    }
    if !session.response_unused {
        return Err(VerificationError::ResponseReplay);
    }
    if !presentation.response_integrity_verified {
        return Err(VerificationError::ResponseIntegrityInvalid);
    }
    if !presentation.audience_verified {
        return Err(VerificationError::AudienceInvalid);
    }
    if presentation.credential_count != 1 {
        return Err(VerificationError::CredentialCountInvalid);
    }
    if !same_format(credential.format, policy.format) {
        return Err(VerificationError::FormatNotAllowed);
    }
    if credential.credential_type.0 != policy.credential_type.0 {
        return Err(VerificationError::CredentialTypeNotAllowed);
    }
    if credential.trust_anchor.0 != policy.allowed_trust_anchor.0 {
        return Err(VerificationError::IssuerNotTrusted);
    }
    if !same_suite(credential.signature_suite, policy.required_signature_suite) {
        return Err(VerificationError::SignatureSuiteNotAllowed);
    }
    if !credential.signature.usable_at(now, policy.max_clock_skew) {
        return Err(VerificationError::SignatureInvalid);
    }
    if !credential.status.usable_at(now, policy.max_status_age) {
        return Err(VerificationError::StatusInvalid);
    }
    if !credential.not_revoked {
        return Err(VerificationError::CredentialRevoked);
    }
    if !credential.claims_well_formed {
        return Err(VerificationError::ClaimsInvalid);
    }
    if credential.disclosures.0 != policy.required_disclosures.0 {
        return Err(VerificationError::DisclosurePolicyNotSatisfied);
    }
    if policy.require_holder_binding
        && (!presentation.holder_binding_verified
            || presentation.holder_key.0 != credential.holder_key.0)
    {
        return Err(VerificationError::HolderBindingInvalid);
    }
    if policy.require_same_subject && !presentation.credentials_share_subject {
        return Err(VerificationError::SubjectBindingInvalid);
    }

    Ok(AcceptCommand {
        session_id: session.id,
        response_id: presentation.response_id,
        credential_type: credential.credential_type,
        issuer: credential.issuer,
        subject: credential.subject,
        disclosures: credential.disclosures,
    })
}

/// Consumes the replay state only after authorization succeeds.
///
/// # Errors
///
/// Returns the failed verification gate and leaves the session unconsumed.
pub const fn accept_once(
    session: &mut VerificationSession,
    presentation: PresentationEvidence,
    credential: CredentialEvidence,
    now: Instant,
) -> Result<AcceptCommand, VerificationError> {
    match authorize_accept(*session, presentation, credential, now) {
        Ok(command) => {
            session.response_unused = false;
            Ok(command)
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    const NOW: Instant = Instant(1_000);

    const fn evidence() -> TimedEvidence {
        TimedEvidence {
            valid_from: Instant(900),
            valid_until: Instant(1_100),
            checked_at: Instant(990),
            accepted: true,
        }
    }

    const fn fixture() -> (
        VerificationSession,
        PresentationEvidence,
        CredentialEvidence,
    ) {
        let policy = VerificationPolicy {
            credential_type: CredentialTypeId(1),
            format: CredentialFormat::SdJwtVc,
            required_disclosures: DisclosureSetId(2),
            allowed_trust_anchor: TrustAnchorId(3),
            required_signature_suite: SignatureSuite::HybridPqV1,
            require_holder_binding: true,
            require_same_subject: true,
            max_clock_skew: 30,
            max_status_age: 60,
        };
        let session = VerificationSession {
            id: SessionId(4),
            request: PresentationRequest {
                id: RequestId(5),
                client_id: ClientId(6),
                nonce: NonceId(7),
                transcript: TranscriptHash(8),
                issued_at: Instant(950),
                expires_at: Instant(1_050),
                policy,
            },
            request_authenticated: true,
            response_unused: true,
        };
        let presentation = PresentationEvidence {
            response_id: ResponseId(9),
            request_id: RequestId(5),
            client_id: ClientId(6),
            nonce: NonceId(7),
            transcript: TranscriptHash(8),
            audience_verified: true,
            response_integrity_verified: true,
            holder_binding_verified: true,
            holder_key: HolderKeyId(10),
            credential_count: 1,
            credentials_share_subject: true,
        };
        let credential = CredentialEvidence {
            format: CredentialFormat::SdJwtVc,
            credential_type: CredentialTypeId(1),
            issuer: IssuerId(11),
            trust_anchor: TrustAnchorId(3),
            subject: SubjectId(12),
            holder_key: HolderKeyId(10),
            disclosures: DisclosureSetId(2),
            signature_suite: SignatureSuite::HybridPqV1,
            signature: evidence(),
            status: evidence(),
            not_revoked: true,
            claims_well_formed: true,
        };
        (session, presentation, credential)
    }

    #[test]
    fn valid_sd_jwt_presentation_is_authorized() {
        let (session, presentation, credential) = fixture();
        let command = authorize_accept(session, presentation, credential, NOW).unwrap();
        assert_eq!(command.subject, SubjectId(12));
        assert_eq!(command.disclosures, DisclosureSetId(2));
    }

    #[test]
    fn mdoc_is_supported_when_selected_by_policy() {
        let (mut session, presentation, mut credential) = fixture();
        session.request.policy.format = CredentialFormat::Mdoc;
        credential.format = CredentialFormat::Mdoc;
        assert!(authorize_accept(session, presentation, credential, NOW).is_ok());
    }

    #[test]
    fn request_binding_fields_are_all_mandatory() {
        let (session, mut presentation, credential) = fixture();
        presentation.nonce = NonceId(99);
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::RequestBindingMismatch)
        );
        let (session, mut presentation, credential) = fixture();
        presentation.transcript = TranscriptHash(99);
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::RequestBindingMismatch)
        );
    }

    #[test]
    fn untrusted_revoked_or_stale_credential_is_rejected() {
        let (session, presentation, mut credential) = fixture();
        credential.trust_anchor = TrustAnchorId(99);
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::IssuerNotTrusted)
        );
        let (session, presentation, mut credential) = fixture();
        credential.not_revoked = false;
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::CredentialRevoked)
        );
        let (session, presentation, mut credential) = fixture();
        credential.status.checked_at = Instant(900);
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::StatusInvalid)
        );
    }

    #[test]
    fn disclosure_and_holder_binding_are_fail_closed() {
        let (session, presentation, mut credential) = fixture();
        credential.disclosures = DisclosureSetId(99);
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::DisclosurePolicyNotSatisfied)
        );
        let (session, mut presentation, credential) = fixture();
        presentation.holder_key = HolderKeyId(99);
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::HolderBindingInvalid)
        );
    }

    #[test]
    fn required_hybrid_pq_suite_rejects_classical_downgrade() {
        let (session, presentation, mut credential) = fixture();
        credential.signature_suite = SignatureSuite::Classical;
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::SignatureSuiteNotAllowed)
        );

        let (mut session, presentation, mut credential) = fixture();
        session.request.policy.required_signature_suite = SignatureSuite::Classical;
        credential.signature_suite = SignatureSuite::Classical;
        assert!(authorize_accept(session, presentation, credential, NOW).is_ok());

        let (mut session, presentation, credential) = fixture();
        session.request.policy.required_signature_suite = SignatureSuite::Classical;
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::SignatureSuiteNotAllowed)
        );
    }

    #[test]
    fn successful_acceptance_consumes_response_exactly_once() {
        let (mut session, presentation, credential) = fixture();
        assert!(accept_once(&mut session, presentation, credential, NOW).is_ok());
        assert_eq!(
            accept_once(&mut session, presentation, credential, NOW),
            Err(VerificationError::ResponseReplay)
        );
    }

    #[test]
    fn failed_acceptance_does_not_consume_response() {
        let (mut session, mut presentation, credential) = fixture();
        presentation.audience_verified = false;
        assert_eq!(
            accept_once(&mut session, presentation, credential, NOW),
            Err(VerificationError::AudienceInvalid)
        );
        assert!(session.response_unused);
    }

    #[test]
    fn every_boolean_security_gate_fails_closed() {
        let (mut session, presentation, credential) = fixture();
        session.request_authenticated = false;
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::RequestNotAuthenticated)
        );

        let (session, mut presentation, credential) = fixture();
        presentation.response_integrity_verified = false;
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::ResponseIntegrityInvalid)
        );

        let (session, presentation, mut credential) = fixture();
        credential.claims_well_formed = false;
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::ClaimsInvalid)
        );
    }
}
