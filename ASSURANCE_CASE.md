# Assurance case

## Claim

Within the explicit model, a Rust `AcceptCommand` cannot be produced unless the
presentation is request-bound, fresh, trusted, non-revoked, policy-conformant,
holder-bound when required, and unused.

## Evidence

- The safe, dependency-free Rust kernel is small enough for direct review.
- Lean proves soundness and the principal acceptance invariants.
- Tamarin proves the modeled authentication and replay properties.
- Unit tests cover both selected formats, success, replay state, and negative
  request, trust, status, disclosure, holder, integrity, audience, and claim
  gates.
- CI runs formatting, tests, strict Clippy, and Lean; the release gate also runs
  the pinned Tamarin/Maude toolchain.

## Assumptions and trusted computing base

The TCB includes Rust and Lean compilers, the Tamarin/Maude toolchain, configured
time, policy and trust stores, entropy and persistent replay storage, protocol
and credential adapters, cryptographic libraries, operating system, deployment,
and operators. Boolean evidence is not proof by itself: only reviewed adapters
may construct it.

## Excluded claim

These artifacts do not establish legal conformity, qualified status, German or
EU authority approval, CAB assessment, certified wallet interoperability, or
correctness of adapters not present in this repository.
