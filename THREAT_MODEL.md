# Threat model

| Threat | Kernel control | Remaining obligation |
|---|---|---|
| Response replay | One-shot session gate and transition | Atomic durable storage across replicas |
| Mix-up or relay | Client, request, nonce, audience, transcript binding | Correct OID4VP/DC API transcript construction |
| Forged credential | Accepted signature and selected trust anchor | Full path, algorithm, and signature validation |
| Quantum-capable forgery (hybrid profile) | Atomic ES256 ∧ ML-DSA-65 acceptance and the `SignatureSuite` policy gate | Key custody, profile freeze governance, and PQ library qualification |
| Suite downgrade | `SignatureSuiteNotAllowed` before signature freshness; no classical fallback for hybrid-required policies | Correct suite attribution by the cryptographic adapter |
| Hybrid component or wrapper mutation | Strict canonical decoding, disclosure commitment, trusted component-key/generation binding, and atomic dual verification | Secure trusted-key resolution and experimental wrapper transport |
| Revoked credential | Fresh status evidence and non-revocation | Authenticated status fetch, cache and fail-closed policy |
| Holder impersonation | Policy-required holder-key equality and proof | KB-JWT or mdoc DeviceAuthentication validation |
| Over-disclosure | Exact disclosure-set equality | Consent UX and canonical claim-set derivation |
| Type confusion | Exact format and credential-type equality | Strict parsing and metadata validation |
| Multi-credential subject confusion | Count and same-subject gates | Extend model before multi-credential acceptance |
| Clock rollback | Bounded time and evidence age checks | Trusted monotonic/wall-clock handling |
| Adapter bypass | Typed `AcceptCommand` boundary | Process architecture and code review enforcement |

Compromise of issuer, holder, verifier, trust store, status authority, or the
runtime is outside the seed symbolic proofs and must be modeled before a
production security claim.
