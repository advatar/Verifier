# EUDI Formal Credential Verifier

A minimal-dependency Rust relying-party verification kernel for the EU Digital
Identity Wallet ecosystem. It follows the assurance architecture of
`../VCIssuer`: normative traceability, a pure safe-Rust decision boundary, Lean
semantic proofs, Tamarin protocol analysis, and explicit adapter contracts.

The kernel accepts structured evidence for both SD-JWT VC and mdoc. It checks:

- authenticated and current presentation requests;
- request ID, client ID, nonce, audience, and session-transcript binding;
- one-shot response use;
- response integrity and exactly one policy-selected credential;
- credential format/type, trust anchor, signature interval, fresh status, and
  non-revocation;
- the policy-selected signature suite, including the isolated hybrid
  post-quantum suite;
- exact selective-disclosure policy;
- cryptographic holder binding and same-subject policy.

Only [`authorize_accept`](rust/verifier-core/src/lib.rs) can produce an
`AcceptCommand`; only that command may release attributes to an application.
The decision kernel is `no_std`, forbids unsafe code, and has no dependencies.

## Hybrid post-quantum support

The workspace verifies the isolated `euwallet-hybrid-pq-v1` profile ported
from `../EUWallet`: atomic ES256 + ML-DSA-65 (FIPS 204) signatures over one
domain-separated byte string, carried in strict magic-prefixed
deterministic-CBOR envelopes.

- [`rust/hybrid-pq`](rust/hybrid-pq) — dependency-free profile types, the
  injective TBS construction, and the strict envelope codec, pinned against
  the wallet repository's published test vectors in
  [docs/test-vectors](docs/test-vectors).
- [`rust/hybrid-pq-verifier`](rust/hybrid-pq-verifier) — the atomic
  verification adapter (`verify_hybrid_signature_atomic`) backed by RustCrypto
  `ml-dsa` and `p256`. Acceptance is AND-only: there is no classical-only or
  post-quantum-only success state, and downgrade attempts fail closed.
- The kernel's `SignatureSuite` gate (proved by
  `required_signature_suite_is_enforced`) ensures a hybrid-required policy can
  never be satisfied by classical-only evidence.

See
[docs/experimental-hybrid-pq-verification.md](docs/experimental-hybrid-pq-verification.md).
The profile is experimental, default-off, non-EUDI, and not a conformity
claim.

## Verify

```sh
cd rust
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

cd ../formal/lean
lake build

cd ../tamarin
tamarin-prover eudi_presentation.spthy --prove
```

The current snapshot contains 33 Rust tests, 7 Lean theorems, and 3 Tamarin
lemmas.

## Assurance boundary

This is a verified verifier **kernel**, not a deployable OpenID4VP endpoint and
not a certification claim. A production adapter must still implement and test
OpenID4VP/DCQL or the Digital Credentials API, JAR/JARM where applicable,
certificate path and verifier/issuer trust, SD-JWT VC and mdoc parsing and
cryptography, status retrieval, algorithm policy, secure persistence, and
official EUDI conformance suites. It must turn those checks into the evidence
types consumed by the kernel without bypassing `AcceptCommand`.

`standards.lock.toml` deliberately keeps `production_ready = false` until
licensed standards, scheme rulebooks, immutable artifacts, hashes, adapters,
and external conformity evidence are complete.

See [FORMAL_SPEC.md](FORMAL_SPEC.md), [ASSURANCE_CASE.md](ASSURANCE_CASE.md),
[THREAT_MODEL.md](THREAT_MODEL.md), and
[requirements/traceability.csv](requirements/traceability.csv).
