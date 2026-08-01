# Status

## EUDI relying-party verifier baseline

- [x] Create the implementation issue and use one issue-scoped branch: [#1](https://github.com/advatar/Verifier/issues/1).
- [x] Pin the applicable EU wallet presentation standards and document the assurance boundary.
- [x] Implement a dependency-free, safe-Rust verification decision kernel for SD-JWT VC and mdoc evidence.
- [x] Prove the kernel's authorization, binding, freshness, disclosure, status, and replay invariants in Lean.
- [x] Model presentation authentication, holder binding, and replay resistance in Tamarin.
- [x] Add conformance-oriented unit tests and CI verification gates.
- [x] Run Rust, Lean, and Tamarin verification.
- [x] Integrate the verified branch into `main` via [PR #2](https://github.com/advatar/Verifier/pull/2).

## Test relying-party frontend

- [x] Create [issue #3](https://github.com/advatar/Verifier/issues/3) and use one issue-scoped branch.
- [x] Build the Lovable test relying party for every credential profile exposed by VCIssuer.
- [x] Add OpenID4VP request generation, wallet launch/copy controls, and verifier-result inspection.
- [x] Validate responsive behavior, lint, and production build.
- [x] Publish the frontend to the Lovable-connected repository via [verifier-page PR #1](https://github.com/advatar/verifier-page/pull/1).
- [x] Integrate the parent repository's verified submodule reference into `main` via [PR #4](https://github.com/advatar/Verifier/pull/4).

## Hybrid post-quantum verification

- [x] Port the frozen `euwallet-hybrid-pq-v1` types, TBS construction, and
      strict envelope codec from `../EUWallet` into `rust/hybrid-pq`.
- [x] Port the atomic ES256 + ML-DSA-65 verification entry point into
      `rust/hybrid-pq-verifier` on the qualified RustCrypto `ml-dsa` pin.
- [x] Pin the wallet repository's published TBS test vectors and ML-DSA-65
      key anchor for cross-repository interoperability.
- [x] Port the frozen credential wrapper, bind its component key IDs and
      generation to trusted state, and verify the shared VCIssuer/EUWallet
      component and wrapper corpora including all 33 mutations.
- [x] Add the kernel `SignatureSuite` gate and prove
      `required_signature_suite_is_enforced` in Lean.
- [x] Port the dedicated Lean and Tamarin hybrid-PQ models for AND-only
      acceptance, downgrade resistance, and quantum-era classical compromise.
- [x] Extend traceability, standards lock, threat model, and assurance case.

## Multi-tenant Lovable application

- [x] Create the continuation issue: [#5](https://github.com/advatar/Verifier/issues/5).
- [x] Document the exact resume point and Lovable write-scope blocker in `RESUME.md`.
- [ ] Enable Lovable Cloud and Google authentication in the Lovable editor.
- [ ] Add organizations, memberships, configurations, transactions, and audit persistence.
- [ ] Enforce and test tenant-isolating RLS policies.
- [ ] Audit, verify, merge, and deploy the generated multi-tenant application.
