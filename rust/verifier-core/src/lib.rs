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

/// A bounded set of authorized operations as a bitmask, mirroring the issuer's `Powers`. One bit
/// per operation keeps scope-containment a decidable `const fn` (`subset_of`). `subset_of` is sound
/// relative to this flat-bitmask abstraction; that the abstraction faithfully models wire scope
/// semantics (and matches the issuer's proven narrowing, whose proof lives in a different repo) is
/// an obligation on the (open) `delegation-verifier` adapter — WIRE-DELEG-001 — which parses a
/// mandate's scope URNs into this bitmask via the pinned power taxonomy, not a fact established here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Powers(pub u64);

impl Powers {
    /// `self ⊆ grant`: every set bit of `self` is also set in `grant`.
    #[must_use]
    pub const fn subset_of(self, grant: Powers) -> bool {
        (self.0 & grant.0) == self.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
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
    /// When set, acceptance additionally requires a valid power-of-representation mandate
    /// (`PresentationEvidence::delegation`) bound to the presenting agent key and granting at least
    /// `required_powers`.
    pub require_delegation: bool,
    /// Trust anchor the mandate attestation must chain to (the delegation issuer).
    pub allowed_delegation_anchor: TrustAnchorId,
    /// Powers this relying party's action needs; must be a subset of the mandate's granted powers.
    pub required_powers: Powers,
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

/// Evidence for a power-of-representation mandate presented alongside the agent's holder credential.
/// Produced by the `delegation-verifier` adapter: parse the mandate VC, resolve the delegator trust
/// anchor, extract the authenticated `cnf` into `delegate_key`, map the mandate's scope URNs into
/// `granted_powers` via the pinned taxonomy, and check the mandate's own signature/status/status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegationEvidence {
    pub delegator_subject: SubjectId,
    /// The mandate's authenticated `cnf` — the agent (delegate) key it is bound to.
    pub delegate_key: HolderKeyId,
    /// Powers the mandate grants the delegate, parsed from the mandate's scope claim.
    pub granted_powers: Powers,
    pub trust_anchor: TrustAnchorId,
    pub signature: TimedEvidence,
    pub status: TimedEvidence,
    pub not_revoked: bool,
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
    /// The power-of-representation mandate presented with the holder credential, if any.
    pub delegation: Option<DelegationEvidence>,
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
    /// For a delegated acceptance: the delegator the agent acted on behalf of, and the powers the
    /// mandate granted. `None` / empty for an ordinary (non-delegated) acceptance.
    pub on_behalf_of: Option<SubjectId>,
    pub granted_powers: Powers,
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
    DelegationMissing,
    DelegationAnchorNotTrusted,
    DelegationSignatureInvalid,
    DelegationStatusInvalid,
    DelegationRevoked,
    DelegateKeyBindingInvalid,
    PowerNotGranted,
}

/// Total, ordered, fail-closed implementation of the canonical `MayAccept`
/// predicate. Equality of `DisclosureSetId` means an adapter has proved the
/// exact policy-selected disclosure set, avoiding accidental over-disclosure.
///
/// # Errors
///
/// Returns the first failed verification gate. No attributes are released.
#[allow(clippy::too_many_lines)]
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
    // A delegated presentation carries the agent's holder credential plus the mandate; an ordinary
    // presentation carries exactly one credential.
    let expected_credentials = if policy.require_delegation { 2 } else { 1 };
    if presentation.credential_count != expected_credentials {
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

    // Power-of-representation gate: when the policy requires a mandate, acceptance additionally
    // proves the mandate is trusted, live, un-revoked, bound to the presenting (possession-proven)
    // agent key, and grants at least the powers this action needs. The scope check
    // `required ⊆ granted` is the decidable wire relation; that it faithfully models the issuer's
    // proven monotonic narrowing is an assumption discharged by the (open) delegation-verifier
    // adapter (WIRE-DELEG-001), not established here.
    if policy.require_delegation {
        match presentation.delegation {
            None => return Err(VerificationError::DelegationMissing),
            Some(delegation) => {
                if delegation.trust_anchor.0 != policy.allowed_delegation_anchor.0 {
                    return Err(VerificationError::DelegationAnchorNotTrusted);
                }
                if !delegation.signature.usable_at(now, policy.max_clock_skew) {
                    return Err(VerificationError::DelegationSignatureInvalid);
                }
                if !delegation.status.usable_at(now, policy.max_status_age) {
                    return Err(VerificationError::DelegationStatusInvalid);
                }
                if !delegation.not_revoked {
                    return Err(VerificationError::DelegationRevoked);
                }
                // The delegate-key binding is meaningful ONLY if the presenting key was actually
                // possession-proven. Require holder binding for any delegated acceptance,
                // independent of `require_holder_binding` — otherwise an adapter-asserted
                // `holder_key` could equal a victim agent's key with no proof of possession.
                if !presentation.holder_binding_verified
                    || delegation.delegate_key.0 != presentation.holder_key.0
                {
                    return Err(VerificationError::DelegateKeyBindingInvalid);
                }
                if !policy.required_powers.subset_of(delegation.granted_powers) {
                    return Err(VerificationError::PowerNotGranted);
                }
            }
        }
    }

    let (on_behalf_of, granted_powers) = match (policy.require_delegation, presentation.delegation)
    {
        (true, Some(delegation)) => (
            Some(delegation.delegator_subject),
            delegation.granted_powers,
        ),
        _ => (None, Powers(0)),
    };

    Ok(AcceptCommand {
        session_id: session.id,
        response_id: presentation.response_id,
        credential_type: credential.credential_type,
        issuer: credential.issuer,
        subject: credential.subject,
        disclosures: credential.disclosures,
        on_behalf_of,
        granted_powers,
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
            require_delegation: false,
            allowed_delegation_anchor: TrustAnchorId(13),
            required_powers: Powers(0),
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
            delegation: None,
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

    const fn classical_fixture() -> (
        VerificationSession,
        PresentationEvidence,
        CredentialEvidence,
    ) {
        let (mut session, presentation, mut credential) = fixture();
        session.request.policy.required_signature_suite = SignatureSuite::Classical;
        credential.signature_suite = SignatureSuite::Classical;
        (session, presentation, credential)
    }

    /// A valid delegated presentation: the RP requires a mandate granting at least `present-identity`
    /// (bit 0), and the agent presents its holder credential plus a mandate from delegator 42 that
    /// grants `present-identity | sign-document` (0b11), bound to the presenting agent key (10).
    fn delegation_fixture() -> (
        VerificationSession,
        PresentationEvidence,
        CredentialEvidence,
    ) {
        let (mut session, mut presentation, credential) = fixture();
        session.request.policy.require_delegation = true;
        session.request.policy.required_powers = Powers(0b01);
        presentation.credential_count = 2;
        presentation.delegation = Some(DelegationEvidence {
            delegator_subject: SubjectId(42),
            delegate_key: HolderKeyId(10),
            granted_powers: Powers(0b11),
            trust_anchor: TrustAnchorId(13),
            signature: evidence(),
            status: evidence(),
            not_revoked: true,
        });
        (session, presentation, credential)
    }

    #[test]
    fn valid_delegated_presentation_is_authorized_on_behalf_of_delegator() {
        let (session, presentation, credential) = delegation_fixture();
        let command = authorize_accept(session, presentation, credential, NOW).unwrap();
        assert_eq!(command.on_behalf_of, Some(SubjectId(42)));
        assert_eq!(command.granted_powers, Powers(0b11));
    }

    #[test]
    fn ordinary_acceptance_has_no_delegation_outcome() {
        let (session, presentation, credential) = fixture();
        let command = authorize_accept(session, presentation, credential, NOW).unwrap();
        assert_eq!(command.on_behalf_of, None);
        assert_eq!(command.granted_powers, Powers(0));
    }

    #[test]
    fn required_power_outside_the_grant_is_rejected() {
        let (mut session, presentation, credential) = delegation_fixture();
        // The RP needs bit 2, which the mandate (0b11) does not grant.
        session.request.policy.required_powers = Powers(0b100);
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::PowerNotGranted)
        );
    }

    #[test]
    fn mandate_bound_to_a_different_agent_key_is_rejected() {
        let (session, mut presentation, credential) = delegation_fixture();
        if let Some(delegation) = presentation.delegation.as_mut() {
            delegation.delegate_key = HolderKeyId(99); // not the presenting agent key (10)
        }
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::DelegateKeyBindingInvalid)
        );
    }

    #[test]
    fn delegated_acceptance_requires_a_possession_proven_holder_key() {
        // Even with holder-binding turned OFF in policy, a delegated acceptance must prove the
        // presenting agent key was possession-proven — else the delegate-key check is hollow.
        let (mut session, mut presentation, credential) = delegation_fixture();
        session.request.policy.require_holder_binding = false;
        presentation.holder_binding_verified = false;
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::DelegateKeyBindingInvalid)
        );
    }

    #[test]
    fn revoked_untrusted_or_missing_mandate_is_rejected() {
        let (session, mut presentation, credential) = delegation_fixture();
        if let Some(delegation) = presentation.delegation.as_mut() {
            delegation.not_revoked = false;
        }
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::DelegationRevoked)
        );

        let (session, mut presentation, credential) = delegation_fixture();
        if let Some(delegation) = presentation.delegation.as_mut() {
            delegation.trust_anchor = TrustAnchorId(99);
        }
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::DelegationAnchorNotTrusted)
        );

        let (session, mut presentation, credential) = delegation_fixture();
        presentation.delegation = None;
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::DelegationMissing)
        );
    }

    #[test]
    fn delegated_presentation_requires_holder_credential_plus_mandate() {
        let (session, mut presentation, credential) = delegation_fixture();
        presentation.credential_count = 1; // missing the second (mandate) credential
        assert_eq!(
            authorize_accept(session, presentation, credential, NOW),
            Err(VerificationError::CredentialCountInvalid)
        );
    }

    #[test]
    fn valid_sd_jwt_presentation_is_authorized() {
        let (session, presentation, credential) = fixture();
        let command = authorize_accept(session, presentation, credential, NOW).unwrap();
        assert_eq!(command.subject, SubjectId(12));
        assert_eq!(command.disclosures, DisclosureSetId(2));
    }

    #[test]
    fn classical_sd_jwt_presentation_remains_authorized() {
        let (session, presentation, credential) = classical_fixture();
        assert!(authorize_accept(session, presentation, credential, NOW).is_ok());
    }

    #[test]
    fn mdoc_is_supported_when_selected_by_policy() {
        let (mut session, presentation, mut credential) = fixture();
        session.request.policy.format = CredentialFormat::Mdoc;
        credential.format = CredentialFormat::Mdoc;
        assert!(authorize_accept(session, presentation, credential, NOW).is_ok());
    }

    #[test]
    fn classical_mdoc_presentation_remains_authorized() {
        let (mut session, presentation, mut credential) = classical_fixture();
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
