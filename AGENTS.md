# Project agent memory

- This repository is a Homebrew tap. Keep formula implementation details in `Formula/pm.rb`, validation in `.github/workflows/homebrew.yml`, and future PM release-bump steps in `docs/formula-bump.md`.
- PM formula updates must use immutable `polymetrics-ai/cli` tag archives with checked SHA-256 values and linker metadata that matches the upstream release; prefer `scripts/pm_formula_bump.rb` and `docs/formula-bump.md` for deterministic bumps.
- Do not add casks, bottles, signing/notarization credentials, release-asset installers, release-write workflow permissions, or self-hosted runner usage without separate approval.
- Repository security guardrails live in `.github/CODEOWNERS`, `.github/workflows/pull-request-authorization.yml`, `SECURITY.md`, and `test/security_guardrails_test.rb`; keep the public tap installable and do not require a self-impossible code-owner approval.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
