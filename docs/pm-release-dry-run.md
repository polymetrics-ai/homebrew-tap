# PM release dry-run verification

Use the `PM release dry-run verification` workflow before any automated formula
branch or pull request work for a released stable PM version. The workflow is
manual, tap-owned, read-only, and intentionally stops before every repository
mutation.

## Run it

1. Open **Actions → PM release dry-run verification → Run workflow** on the tap's
   default branch.
2. Set:
   - `version`: stable PM version without `v`, such as `0.1.1`.
   - `release_id`: optional but recommended GitHub Release id to cross-check.
   - `source_run_id`: optional upstream Release workflow run id expected in
     Sigstore certificate evidence.
   - `target_commitish_policy`: leave `ignore` for normal dry-runs. Use
     `require-full-sha` only for an explicit audit that requires the release's
     `target_commitish` field to be a full SHA matching the immutable tag commit.
3. Keep `dispatch_schema` and `source_repo` at their defaults.

The verifier treats every input and every GitHub release field as untrusted. It
constructs `refs/tags/v<version>` itself and uses the resolved tag commit as the
authority, not a mutable branch-valued release `target_commitish`.

## What it verifies

The workflow runs `scripts/pm_release_verifier.rb verify`, which reuses the
formula bump planner for deterministic Formula/README metadata and then verifies:

- stable version and optional release id/run id inputs;
- non-draft, non-prerelease GitHub Release for the exact tag;
- immutable tag commit, commit date, source archive URL, source archive SHA-256,
  and required source archive paths;
- exact PM release asset inventory: ten archives/packages, `checksums.txt`, and
  one `.sigstore.json` bundle for every signed subject;
- checksum manifest coverage and bindings to downloaded asset bytes;
- release asset API SHA-256 digests;
- Cosign bundle signatures, Fulcio/Rekor evidence, and exact GitHub Actions
  certificate identity for the PM release workflow using `cosign verify-blob`;
- GitHub artifact attestation trust, exact certificate identity, and complete
  subject bindings using `gh attestation verify`;
- dry-run Formula/README selection with no tracked file changes.

The workflow fails on invalid input, release/tag mismatch, source metadata drift,
missing/duplicate/unexpected/not-uploaded assets, checksum mismatch, signature or
certificate mismatch, missing/ambiguous attestation evidence, or any tracked file
mutation.

## Interpret results

A successful run writes two JSON blocks to the GitHub step summary:

- **Verification summary**: release id, policy, Formula/README dry-run result,
  and verified asset counts/names.
- **Deterministic formula metadata**: the exact version, source URL, source
  SHA-256, tag commit, and build date that a future formula branch would use.

Success means the released PM version is eligible for a later formula-update
branch/PR slice. It does **not** create or update a branch, commit, PR, formula,
README, release, tag, bottle, cask, secret, App, or repository setting.

## Local development

Local dry-runs require `cosign` and the GitHub CLI's `gh attestation verify`
command on `PATH`. Run the focused tests with:

```sh
ruby test/pm_release_verifier_test.rb
ruby test/security_guardrails_test.rb
ruby test/pm_formula_bump_test.rb
```

For a public immutable end-to-end replay, use a temp directory outside tracked
repo paths and do not provide credentials. If the unauthenticated GitHub API
rate-limits with HTTP 403, rerun later or use the manual workflow's read-only
`GITHUB_TOKEN` instead of a local PAT or App credential:

```sh
metadata_dir="$(mktemp -d)"
trap 'rm -rf "$metadata_dir"' EXIT
unset GITHUB_TOKEN
ruby scripts/pm_release_verifier.rb verify \
  --dispatch-schema pm-homebrew-release-dry-run/v1 \
  --source-repo polymetrics-ai/cli \
  --version 0.1.1 \
  --release-id 361072189 \
  --source-run-id 30359194501 \
  --target-commitish-policy ignore \
  --metadata-out "$metadata_dir/pm-formula-metadata.json" \
  --verification-out "$metadata_dir/pm-release-verification.json" \
  --formula Formula/pm.rb \
  --readme README.md
```
