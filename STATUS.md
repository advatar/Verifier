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
