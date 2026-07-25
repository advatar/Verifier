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
