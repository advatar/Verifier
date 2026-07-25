# Formal specification

## Security boundary

Untrusted bytes are parsed and cryptographically checked by format adapters.
Adapters may construct evidence only after their complete contract succeeds.
The pure kernel maps that evidence and a configured policy to either a typed
failure or an `AcceptCommand`. Application code may consume claims only from
that command.

```text
wallet bytes -> protocol/format/PKI/status adapters -> structured evidence
             -> authorize_accept -> AcceptCommand -> application claims
```

## Canonical predicate

`MayAccept(s, p, c, now)` is the conjunction encoded in
`formal/lean/EudiVerifier/Model.lean` and implemented in
`rust/verifier-core/src/lib.rs`:

1. The verifier request is authenticated and current under bounded clock skew.
2. Response request ID, client ID, nonce, and transcript equal the request.
3. The response is unused, integrity protected, audience bound, and contains
   exactly the credential count supported by this baseline.
4. Format, credential type, and trust anchor equal the selected policy.
5. Signature and status evidence are accepted, in interval, and fresh.
6. The credential is not revoked and claims are structurally valid.
7. The disclosed set exactly equals the policy-approved set.
8. Required holder-key and subject binding hold.

The operational `accept_once` transition changes `response_unused` to false
only after `authorize_accept` succeeds.

## Proved properties

- `authorizeAccept_sound`: every command implies `MayAccept`.
- `accepted_response_is_request_bound`: request/client/nonce/transcript match.
- `replayed_response_cannot_be_accepted`: consumed responses fail closed.
- `accepted_credential_is_trusted_and_current`: trust, signature, fresh status,
  and non-revocation hold.
- `accepted_disclosures_match_policy`: no unapproved disclosure set is released.
- `required_holder_binding_is_enforced`: required possession binds to the
  credential holder key.

The Tamarin model separately proves request precedence, authentic holder
presentation precedence, and nonce injectivity in its symbolic scope.

## Adapter obligations

For SD-JWT VC, adapters must verify the issuer JWT, `_sd` disclosure digests,
type metadata policy, `cnf`/KB-JWT proof, `aud`, nonce, time, algorithm, issuer
chain, and status. For mdoc, adapters must verify CBOR deterministically,
IssuerAuth/MSO/device namespaces, value digests, validity, certificate path,
DeviceAuthentication, and the OID4VP/DC API session transcript. Both adapters
must reject duplicates, ambiguity, unsupported critical data, and trailing
input, and must preserve the exact disclosed claim set.

