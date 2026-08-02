# Assurance case

## Claim

Within the explicit model, a Rust `AcceptCommand` cannot be produced unless the
presentation is request-bound, fresh, trusted, non-revoked, policy-conformant,
holder-bound when required, and unused.

## Evidence

- The safe, dependency-free Rust kernel is small enough for direct review;
  the hybrid post-quantum adapter crates isolate their pinned RustCrypto
  dependencies (`ml-dsa`, `p256`) outside the kernel boundary.
- Lean proves soundness and the principal acceptance invariants, including
  signature-suite downgrade resistance.
- Tamarin proves the modeled authentication and replay properties.
- Unit tests cover classical and hybrid success for both selected formats,
  replay state, and negative
  request, trust, status, disclosure, holder, integrity, audience, claim, and
  signature-suite gates, plus the atomic hybrid ES256 ∧ ML-DSA-65 two-by-two
  validity matrix, strict envelope negatives, the shared VCIssuer/EUWallet
  component and credential-wrapper corpora (including 33 mutations), and the
  wallet repository's published TBS vectors and ML-DSA key anchor.
- Dedicated Lean and Tamarin hybrid-PQ models prove AND-only acceptance,
  identity/generation and purpose binding, downgrade resistance, and that
  classical compromise alone is insufficient.
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
