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
- exact selective-disclosure policy;
- cryptographic holder binding and same-subject policy.

Only [`authorize_accept`](rust/verifier-core/src/lib.rs) can produce an
`AcceptCommand`; only that command may release attributes to an application.
The decision kernel is `no_std`, forbids unsafe code, and has no dependencies.

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

The current snapshot contains 8 Rust tests, 5 Lean theorems, and 3 Tamarin
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
