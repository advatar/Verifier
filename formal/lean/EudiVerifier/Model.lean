/-!
Canonical EUDI relying-party acceptance model.

Cryptographic and wire-format adapters establish structured evidence. This
model defines the only transition that may release verified attributes.
-/

namespace EudiVerifier

abbrev Instant := Nat
abbrev SessionId := Nat
abbrev RequestId := Nat
abbrev ResponseId := Nat
abbrev ClientId := Nat
abbrev NonceId := Nat
abbrev TranscriptHash := Nat
abbrev CredentialTypeId := Nat
abbrev IssuerId := Nat
abbrev TrustAnchorId := Nat
abbrev HolderKeyId := Nat
abbrev SubjectId := Nat
abbrev DisclosureSetId := Nat

inductive CredentialFormat where
  | sdJwtVc
  | mdoc
  deriving DecidableEq, Repr

/-- Signature suite proved by the cryptographic adapter. `hybridPqV1` records
atomic verification of both the ES256 and ML-DSA-65 components of the isolated
`euwallet-hybrid-pq-v1` profile over identical domain-separated bytes. -/
inductive SignatureSuite where
  | classical
  | hybridPqV1
  deriving DecidableEq, Repr

/-- A bounded set of authorized operations as a bitmask, mirroring the issuer's `Powers`. One bit
per operation keeps scope-containment a decidable relation (`subsetOf`). -/
abbrev Powers := Nat

/-- `a ⊆ grant`: every set bit of `a` is also set in `grant`. Mirrors the Rust
`(a & grant) == a` and the issuer kernel's proven monotonic narrowing. -/
def Powers.subsetOf (a grant : Powers) : Prop := Nat.land a grant = a

structure TimedEvidence where
  validFrom : Instant
  validUntil : Instant
  checkedAt : Instant
  accepted : Bool
  deriving DecidableEq, Repr

def TimedEvidence.usableAt (e : TimedEvidence) (now maxAge : Nat) : Prop :=
  e.accepted = true ∧
  e.validFrom ≤ now ∧
  now < e.validUntil ∧
  e.checkedAt ≤ now ∧
  now - e.checkedAt ≤ maxAge

structure VerificationPolicy where
  credentialType : CredentialTypeId
  format : CredentialFormat
  requiredDisclosures : DisclosureSetId
  allowedTrustAnchor : TrustAnchorId
  requiredSignatureSuite : SignatureSuite
  requireHolderBinding : Bool
  requireSameSubject : Bool
  maxClockSkew : Nat
  maxStatusAge : Nat
  requireDelegation : Bool
  allowedDelegationAnchor : TrustAnchorId
  requiredPowers : Powers
  deriving DecidableEq, Repr

structure PresentationRequest where
  id : RequestId
  clientId : ClientId
  nonce : NonceId
  transcript : TranscriptHash
  issuedAt : Instant
  expiresAt : Instant
  policy : VerificationPolicy
  deriving DecidableEq, Repr

structure CredentialEvidence where
  format : CredentialFormat
  credentialType : CredentialTypeId
  issuer : IssuerId
  trustAnchor : TrustAnchorId
  subject : SubjectId
  holderKey : HolderKeyId
  disclosures : DisclosureSetId
  signatureSuite : SignatureSuite
  signature : TimedEvidence
  status : TimedEvidence
  notRevoked : Bool
  claimsWellFormed : Bool
  deriving DecidableEq, Repr

/-- Evidence for a power-of-representation mandate presented with the agent's holder credential. -/
structure DelegationEvidence where
  delegatorSubject : SubjectId
  delegateKey : HolderKeyId
  grantedPowers : Powers
  trustAnchor : TrustAnchorId
  signature : TimedEvidence
  status : TimedEvidence
  notRevoked : Bool
  deriving DecidableEq, Repr

structure PresentationEvidence where
  responseId : ResponseId
  requestId : RequestId
  clientId : ClientId
  nonce : NonceId
  transcript : TranscriptHash
  audienceVerified : Bool
  responseIntegrityVerified : Bool
  holderBindingVerified : Bool
  holderKey : HolderKeyId
  credentialCount : Nat
  credentialsShareSubject : Bool
  delegation : Option DelegationEvidence
  deriving DecidableEq, Repr

structure VerificationSession where
  id : SessionId
  request : PresentationRequest
  requestAuthenticated : Bool
  responseUnused : Bool
  deriving DecidableEq, Repr

def requestCurrent (r : PresentationRequest) (now : Instant) : Prop :=
  r.issuedAt ≤ now + r.policy.maxClockSkew ∧
  now < r.expiresAt + r.policy.maxClockSkew

def holderBindingOk (policy : VerificationPolicy)
    (p : PresentationEvidence) (c : CredentialEvidence) : Prop :=
  policy.requireHolderBinding = false ∨
    (p.holderBindingVerified = true ∧ p.holderKey = c.holderKey)

def subjectBindingOk (policy : VerificationPolicy)
    (p : PresentationEvidence) : Prop :=
  policy.requireSameSubject = false ∨ p.credentialsShareSubject = true

/-- A delegated presentation carries the holder credential plus the mandate (two credentials); an
ordinary presentation carries exactly one. -/
def expectedCredentialCount (policy : VerificationPolicy) : Nat :=
  if policy.requireDelegation = true then 2 else 1

/-- Power-of-representation gate: when the policy requires a mandate, acceptance additionally proves
a trusted, live, un-revoked mandate bound to the presenting agent key and granting at least the
powers this action needs. `requiredPowers ⊆ grantedPowers` is the decidable wire mirror of the
issuer's proven monotonic narrowing. -/
def delegationOk (policy : VerificationPolicy) (p : PresentationEvidence) (now : Instant) : Prop :=
  policy.requireDelegation = false ∨
    (∃ d, p.delegation = some d ∧
      d.trustAnchor = policy.allowedDelegationAnchor ∧
      d.signature.usableAt now policy.maxClockSkew ∧
      d.status.usableAt now policy.maxStatusAge ∧
      d.notRevoked = true ∧
      p.holderBindingVerified = true ∧
      d.delegateKey = p.holderKey ∧
      Powers.subsetOf policy.requiredPowers d.grantedPowers)

def mayAccept (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) : Prop :=
  s.requestAuthenticated = true ∧
  requestCurrent s.request now ∧
  p.requestId = s.request.id ∧
  p.clientId = s.request.clientId ∧
  p.nonce = s.request.nonce ∧
  p.transcript = s.request.transcript ∧
  s.responseUnused = true ∧
  p.responseIntegrityVerified = true ∧
  p.audienceVerified = true ∧
  p.credentialCount = expectedCredentialCount s.request.policy ∧
  c.format = s.request.policy.format ∧
  c.credentialType = s.request.policy.credentialType ∧
  c.trustAnchor = s.request.policy.allowedTrustAnchor ∧
  c.signatureSuite = s.request.policy.requiredSignatureSuite ∧
  c.signature.usableAt now s.request.policy.maxClockSkew ∧
  c.status.usableAt now s.request.policy.maxStatusAge ∧
  c.notRevoked = true ∧
  c.claimsWellFormed = true ∧
  c.disclosures = s.request.policy.requiredDisclosures ∧
  holderBindingOk s.request.policy p c ∧
  subjectBindingOk s.request.policy p ∧
  delegationOk s.request.policy p now

noncomputable instance mayAcceptDecidable
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) :
    Decidable (mayAccept s p c now) := Classical.propDecidable _

inductive Error where
  | notAuthorized
  deriving DecidableEq, Repr

structure AcceptCommand where
  sessionId : SessionId
  responseId : ResponseId
  credentialType : CredentialTypeId
  issuer : IssuerId
  subject : SubjectId
  disclosures : DisclosureSetId
  onBehalfOf : Option SubjectId
  grantedPowers : Powers
  deriving DecidableEq, Repr

/-- The delegator a delegated acceptance acted on behalf of (mirrors the Rust tuple match). -/
def onBehalfOfFor (policy : VerificationPolicy) (p : PresentationEvidence) : Option SubjectId :=
  match policy.requireDelegation, p.delegation with
  | true, some d => some d.delegatorSubject
  | _, _ => none

/-- The powers a delegated acceptance exercised; empty for an ordinary acceptance. -/
def grantedPowersFor (policy : VerificationPolicy) (p : PresentationEvidence) : Powers :=
  match policy.requireDelegation, p.delegation with
  | true, some d => d.grantedPowers
  | _, _ => 0

noncomputable def authorizeAccept
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) : Except Error AcceptCommand :=
  if _h : mayAccept s p c now then
    .ok {
      sessionId := s.id
      responseId := p.responseId
      credentialType := c.credentialType
      issuer := c.issuer
      subject := c.subject
      disclosures := c.disclosures
      onBehalfOf := onBehalfOfFor s.request.policy p
      grantedPowers := grantedPowersFor s.request.policy p
    }
  else
    .error .notAuthorized

/-- A released command implies every acceptance gate. -/
theorem authorizeAccept_sound
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) (cmd : AcceptCommand)
    (h : authorizeAccept s p c now = .ok cmd) :
    mayAccept s p c now := by
  unfold authorizeAccept at h
  split at h
  next hMay => exact hMay
  next _ => cases h

/-- Acceptance is bound to the authenticated request and transcript. -/
theorem accepted_response_is_request_bound
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) (cmd : AcceptCommand)
    (h : authorizeAccept s p c now = .ok cmd) :
    p.requestId = s.request.id ∧
    p.clientId = s.request.clientId ∧
    p.nonce = s.request.nonce ∧
    p.transcript = s.request.transcript := by
  have hMay := authorizeAccept_sound s p c now cmd h
  rcases hMay with ⟨_, _, hReq, hClient, hNonce, hTranscript, _⟩
  exact ⟨hReq, hClient, hNonce, hTranscript⟩

/-- A consumed response cannot be accepted again. -/
theorem replayed_response_cannot_be_accepted
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant)
    (hUsed : s.responseUnused = false) :
    authorizeAccept s p c now = .error .notAuthorized := by
  simp [authorizeAccept, mayAccept, hUsed]

/-- Acceptance implies trust, validity, fresh status, and non-revocation. -/
theorem accepted_credential_is_trusted_and_current
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) (cmd : AcceptCommand)
    (h : authorizeAccept s p c now = .ok cmd) :
    c.trustAnchor = s.request.policy.allowedTrustAnchor ∧
    c.signature.usableAt now s.request.policy.maxClockSkew ∧
    c.status.usableAt now s.request.policy.maxStatusAge ∧
    c.notRevoked = true := by
  have hMay := authorizeAccept_sound s p c now cmd h
  rcases hMay with
    ⟨_, _, _, _, _, _, _, _, _, _, _, _, hTrust, _, hSig, hStatus, hNotRevoked, _⟩
  exact ⟨hTrust, hSig, hStatus, hNotRevoked⟩

/-- Only the policy-approved selective disclosure set may be released. -/
theorem accepted_disclosures_match_policy
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) (cmd : AcceptCommand)
    (h : authorizeAccept s p c now = .ok cmd) :
    c.disclosures = s.request.policy.requiredDisclosures := by
  have hMay := authorizeAccept_sound s p c now cmd h
  rcases hMay with
    ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, hDisclosures, _⟩
  exact hDisclosures

/-- Acceptance proves the policy-selected signature suite: a policy that
requires the hybrid post-quantum suite can never release attributes on
classical-only signature evidence. -/
theorem required_signature_suite_is_enforced
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) (cmd : AcceptCommand)
    (h : authorizeAccept s p c now = .ok cmd) :
    c.signatureSuite = s.request.policy.requiredSignatureSuite := by
  have hMay := authorizeAccept_sound s p c now cmd h
  rcases hMay with
    ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, hSuite, _⟩
  exact hSuite

/-- When policy requires it, acceptance proves possession of the credential key. -/
theorem required_holder_binding_is_enforced
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) (cmd : AcceptCommand)
    (hRequired : s.request.policy.requireHolderBinding = true)
    (h : authorizeAccept s p c now = .ok cmd) :
    p.holderBindingVerified = true ∧ p.holderKey = c.holderKey := by
  have hMay := authorizeAccept_sound s p c now cmd h
  rcases hMay with
    ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, hBinding, _⟩
  simp [holderBindingOk, hRequired] at hBinding
  exact hBinding

/-! ## Power-of-representation (delegation) acceptance theorems

Mirror of the VCVerifier `verifier-core` delegation gate. They establish that a delegated
acceptance can only occur within the powers the mandate grants, bound to the presenting agent key,
while the mandate is trusted and non-revoked — the verifier-side half of the one delegation
property proved on both stacks. -/

/-- `mayAccept` entails the delegation gate (the 22nd conjunct). -/
theorem mayAccept_delegationOk
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) (h : mayAccept s p c now) :
    delegationOk s.request.policy p now := by
  rcases h with
    ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, hDeleg⟩
  exact hDeleg

/-- On a released command, the delegation outcome fields are exactly the selector values. -/
theorem authorizeAccept_ok_fields
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) (cmd : AcceptCommand)
    (h : authorizeAccept s p c now = .ok cmd) :
    cmd.onBehalfOf = onBehalfOfFor s.request.policy p ∧
      cmd.grantedPowers = grantedPowersFor s.request.policy p := by
  unfold authorizeAccept at h
  split at h
  next _ =>
    injection h with hcmd
    subst hcmd
    exact ⟨rfl, rfl⟩
  next _ => cases h

/-- Headline: a delegated acceptance proves a trusted, non-revoked mandate, bound to the presenting
agent key, granting at least the required powers, and records the delegator + granted powers. -/
theorem accepted_delegation_is_scoped_bound_and_live
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) (cmd : AcceptCommand)
    (hReq : s.request.policy.requireDelegation = true)
    (h : authorizeAccept s p c now = .ok cmd) :
    ∃ d, p.delegation = some d ∧
      d.trustAnchor = s.request.policy.allowedDelegationAnchor ∧
      d.notRevoked = true ∧
      d.delegateKey = p.holderKey ∧
      Powers.subsetOf s.request.policy.requiredPowers d.grantedPowers ∧
      cmd.onBehalfOf = some d.delegatorSubject ∧
      cmd.grantedPowers = d.grantedPowers := by
  have hMay := authorizeAccept_sound s p c now cmd h
  have hDeleg := mayAccept_delegationOk s p c now hMay
  have hFields := authorizeAccept_ok_fields s p c now cmd h
  simp only [delegationOk] at hDeleg
  rcases hDeleg with hNo | hEx
  · rw [hReq] at hNo; exact absurd hNo (by decide)
  · obtain ⟨d, hSome, hAnchor, _hSig, _hStatus, hRev, _hBinding, hKey, hSubset⟩ := hEx
    refine ⟨d, hSome, hAnchor, hRev, hKey, hSubset, ?_, ?_⟩
    · rw [hFields.1]; simp only [onBehalfOfFor, hReq, hSome]
    · rw [hFields.2]; simp only [grantedPowersFor, hReq, hSome]

/-- A delegated acceptance proves the presenting agent key was possession-proven (holder binding),
independent of `requireHolderBinding` — so the delegate-key binding can never be hollow. -/
theorem delegated_acceptance_requires_holder_binding
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) (cmd : AcceptCommand)
    (hReq : s.request.policy.requireDelegation = true)
    (h : authorizeAccept s p c now = .ok cmd) :
    p.holderBindingVerified = true := by
  have hMay := authorizeAccept_sound s p c now cmd h
  have hDeleg := mayAccept_delegationOk s p c now hMay
  simp only [delegationOk] at hDeleg
  rcases hDeleg with hNo | hEx
  · rw [hReq] at hNo; exact absurd hNo (by decide)
  · obtain ⟨_d, _hSome, _hAnchor, _hSig, _hStatus, _hRev, hBinding, _hKey, _hSubset⟩ := hEx
    exact hBinding

/-- The mandate is cryptographically bound to the presenting agent key. -/
theorem delegate_key_binding_is_enforced
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) (cmd : AcceptCommand)
    (hReq : s.request.policy.requireDelegation = true)
    (h : authorizeAccept s p c now = .ok cmd) :
    ∃ d, p.delegation = some d ∧ d.delegateKey = p.holderKey := by
  obtain ⟨d, hSome, _, _, hKey, _, _, _⟩ :=
    accepted_delegation_is_scoped_bound_and_live s p c now cmd hReq h
  exact ⟨d, hSome, hKey⟩

/-- A delegated request can only exercise powers within the mandate's grant (monotonic narrowing). -/
theorem delegated_request_is_within_granted_scope
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) (cmd : AcceptCommand)
    (hReq : s.request.policy.requireDelegation = true)
    (h : authorizeAccept s p c now = .ok cmd) :
    ∃ d, p.delegation = some d ∧
      Powers.subsetOf s.request.policy.requiredPowers d.grantedPowers := by
  obtain ⟨d, hSome, _, _, _, hSubset, _, _⟩ :=
    accepted_delegation_is_scoped_bound_and_live s p c now cmd hReq h
  exact ⟨d, hSome, hSubset⟩

/-- A revoked mandate cannot yield a delegated acceptance. -/
theorem revoked_delegation_cannot_be_accepted
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) (cmd : AcceptCommand)
    (hReq : s.request.policy.requireDelegation = true)
    (h : authorizeAccept s p c now = .ok cmd) :
    ∃ d, p.delegation = some d ∧ d.notRevoked = true := by
  obtain ⟨d, hSome, _, hRev, _, _, _, _⟩ :=
    accepted_delegation_is_scoped_bound_and_live s p c now cmd hReq h
  exact ⟨d, hSome, hRev⟩

/-- A delegated acceptance records the delegator it acted on behalf of. -/
theorem delegator_is_recorded_on_behalf_of
    (s : VerificationSession) (p : PresentationEvidence)
    (c : CredentialEvidence) (now : Instant) (cmd : AcceptCommand)
    (hReq : s.request.policy.requireDelegation = true)
    (h : authorizeAccept s p c now = .ok cmd) :
    ∃ d, p.delegation = some d ∧ cmd.onBehalfOf = some d.delegatorSubject := by
  obtain ⟨d, hSome, _, _, _, _, hOnBehalf, _⟩ :=
    accepted_delegation_is_scoped_bound_and_live s p c now cmd hReq h
  exact ⟨d, hSome, hOnBehalf⟩

end EudiVerifier

