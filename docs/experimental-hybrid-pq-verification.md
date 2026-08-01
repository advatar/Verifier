# Experimental hybrid post-quantum verification

This repository verifies artifacts of the isolated `euwallet-hybrid-pq-v1`
profile defined and frozen in `../EUWallet` (see its
`docs/experimental-hybrid-pq-profile-v1.md`, `experimental-hybrid-pq-tbs-v1.md`,
`experimental-hybrid-pq-envelope-v1.md`, `experimental-pq-atomic-verification.md`,
and `docs/adr/0001-isolate-experimental-hybrid-pq.md`). The wallet repository is
normative for the profile; this repository ports the verifier-relevant subset
without redefining any wire byte.

## Frozen algorithm suite

| Function | Choice | Encoding |
|---|---|---|
| Classical signature | ES256 (ECDSA P-256 / SHA-256) | 64-byte `r ‖ s`; 65-byte uncompressed SEC1 public key |
| Post-quantum signature | ML-DSA-65 (FIPS 204) | 1952-byte public key, 3309-byte signature |
| Hash | SHA-256 | — |

Acceptance is **AND and atomic**: one container carries both mandatory
components over the identical domain-separated to-be-signed bytes. There is no
classical-only or post-quantum-only success state, and a `hybrid-required`
policy never falls back to classical.

## Ported components

- `rust/hybrid-pq` — dependency-free types, the injective
  `EUWALLET-HYBRID-SIGNATURE-V1` / `EUWALLET-HYBRID-CONTEXT-V1` TBS
  construction, and the strict deterministic-CBOR envelopes behind the
  `EUWALLET-EXPERIMENTAL-HYBRID-PQ-V1\0` magic prefix. The published TBS test
  vectors in `docs/test-vectors/` are byte-identical to the wallet repository's
  and are pinned by `stable_export_vector_pins_the_construction`.
- `rust/hybrid-pq-verifier` — the atomic verification entry point
  `verify_hybrid_signature_atomic` plus `verify_es256` / `verify_ml_dsa_65`,
  backed by RustCrypto `ml-dsa` 0.1.1 (the wallet repository's qualified pin)
  and `p256` 0.13.2. The `ml_dsa_public_key_matches_the_cross_repo_anchor`
  test reproduces the wallet repository's deterministic ML-DSA-65 key anchor.
- `rust/verifier-core` — a `SignatureSuite` policy gate: credential evidence
  now records which suite its adapter proved, and
  `VerificationError::SignatureSuiteNotAllowed` rejects any suite/policy
  mismatch before signature freshness is considered. Mirrored in Lean by
  `required_signature_suite_is_enforced`.

## Isolation invariants preserved

- Hybrid artifacts are structurally disjoint from SD-JWT VC, mdoc, JOSE, COSE,
  and X.509: the mandatory magic prefix means they can never parse as a
  production credential, and production parsers must not dispatch on it.
- `HybridSignatureProfile` is a distinct type; it does not extend any
  certified algorithm registry and has no JOSE/COSE conversions.
- The closed purpose registry is enforced; unknown purposes and the
  `euwallet-hybrid-pq-v2` probe fail closed.
- Every rejection is externally uniform ("hybrid signature rejected") with
  only a bounded diagnostic class for local tests and telemetry.
- Any change to algorithms, sizes, encodings, framing, canonicalization,
  identifiers, or purpose semantics requires a new profile identifier.

## Excluded scope

Key generation, signing, custody, export/recovery use cases, rollout gates,
and the P-256 + ML-KEM-768 key-establishment combiner remain wallet-side and
are not ported. This profile is experimental, default-off, non-EUDI, and not a
production or conformity claim.
