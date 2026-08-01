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
  p.credentialCount = 1 ∧
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
  subjectBindingOk s.request.policy p

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
  deriving DecidableEq, Repr

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

end EudiVerifier

