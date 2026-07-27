# Resume point

Last updated: 2026-07-27 (Europe/Stockholm)

## Current state

- The formally specified Rust verifier kernel is merged into `VCVerifier/main`.
- The Lovable frontend is merged into `advatar/verifier-page/main` at `21f2cebf14adf857c40584a5b5c971565f11a433`.
- The parent repository records that frontend revision as the `LandingPage` submodule.
- Lovable project: `Verifier Page` (`2a9d428c-5f33-4390-931d-85c70725e78b`).
- Published URL: <https://verifier-is-here.lovable.app>.
- Lovable editor: <https://lovable.dev/projects/2a9d428c-5f33-4390-931d-85c70725e78b>.

## Blocker

The next phase is a real multi-tenant application using Lovable Cloud, Google
sign-in, PostgreSQL/Supabase persistence, and tenant-isolating RLS. The Lovable
MCP credential available to Codex returned `403 insufficient_scope` because it
lacks `projects:write`; therefore the production specification must be pasted
into the Lovable editor by the user, or the connector must be reauthorized with
write scope.

## Resume procedure

1. Ask whether the multi-tenant Lovable build has completed.
2. Pull `advatar/verifier-page/main` and update the `LandingPage` submodule.
3. Inspect every migration, function, authentication callback, and RLS policy.
4. Prove with tests that a member of tenant A cannot read or mutate tenant B.
5. Confirm Google OAuth redirect URLs, secrets, and production-domain settings.
6. Run frontend lint/tests/build and the Rust/Lean/Tamarin verifier gates.
7. Fix findings on one issue-scoped branch, merge it, update the submodule
   pointer, deploy Lovable, and confirm the deployed commit.

## Important boundary

The current frontend can construct DCQL requests and use a configured
`VITE_VERIFIER_API_URL`, but its unconfigured sandbox response is explicitly a
simulation. Only the external Rust protocol/cryptographic adapter may produce a
production accepted result.
