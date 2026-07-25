import Lake
open Lake DSL

package «eudi-verifier-model» where

@[default_target]
lean_lib EudiVerifier where
  srcDir := "."
  roots := #[`EudiVerifier.Model]

