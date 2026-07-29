# PM formula bump checklist

Use this checklist for future immutable PM tags. Do not use moving branches,
unchecked archives, direct release assets, bottles, or provenance changes unless
that work has been separately approved.

## Read-only release dry-run

Before any automated formula branch or PR mutation, run the tap-owned manual
`PM release dry-run verification` workflow documented in
[`pm-release-dry-run.md`](pm-release-dry-run.md). Treat a successful dry-run as a
prerequisite for the formula-update branch/PR path.

The current `PM formula update` workflow repeats the same release verification
before preparing a PR. Use `dry_run=true` for safe manual replays; a successful
`v0.1.1` replay is expected to report `already-current` against the current
formula and must not create a remote branch or PR.

## Automated formula PR path

After the upstream PM release-assets job has completed and a dry-run has proved
the immutable release evidence, dispatch `.github/workflows/pm-formula-update.yml`
on `main` with `dispatch_schema=pm-homebrew-formula/v1`, `source_repo=polymetrics-ai/cli`,
`tag=vX.Y.Z`, and `dry_run=false`. Optional `release_id` and `source_run_id`
inputs are cross-checks only; the workflow re-queries GitHub and derives the
Formula/README metadata from the immutable tag, release assets, checksums,
Cosign bundles, GitHub attestations, and source archive.

The default-branch workflow keeps its `GITHUB_TOKEN` read-only. Only the
`prepare-pr` job uses the protected `homebrew-formula-automation` environment to
mint a short-lived `pm-homebrew-pr-bot` installation token. That token may create
or converge exactly one same-repository branch, `pm-release/vX.Y.Z`, and one
matching PR; it is not permitted or expected to update `main`, bypass branch
protection, publish bottles/casks, or expose secret values in logs.

Expected idempotence states:

- `already-current`: success no-op; no branch/PR mutation.
- `newer-formula`: no downgrade; no branch/PR mutation.
- `metadata-conflict`: fail for manual review; no branch/PR mutation.
- absent deterministic branch: create `pm-release/vX.Y.Z`, commit generated
  `Formula/pm.rb` and `README.md`, and open the matching PR.
- duplicate dispatch/existing open PR: reuse the exact deterministic branch and
  update the existing PR body rather than creating another PR.
- stale bot-owned deterministic branch: reset only with `--force-with-lease`
  after the branch contents already match the verified metadata and the branch
  contains only bot-authored allowlisted formula/README changes.
- human-authored, forked, divergent, workflow, CODEOWNERS, security, or policy
  changes: refuse or auto-close through PR authorization without checkout of PR
  code.

## Retry, rollback, and manual fallback

- **Validation fails before mutation:** fix the release, verifier, or dispatch
  input and rerun `dry_run=true`. No branch exists.
- **Automation fails after branch creation:** rerun the same `dry_run=false`
  dispatch. The workflow is version-concurrent and converges the deterministic
  branch/PR instead of creating duplicates.
- **Bot PR is wrong:** close the PR, delete only the `pm-release/vX.Y.Z` branch
  after inspection, fix the workflow/script/tests, and rerun from `dry_run=true`.
  Do not retag or push to `main`.
- **Bad formula merges:** open a normal maintainer PR reverting the formula
  commit or restoring the last known-good immutable tag, checksum, and linker
  metadata. Do not grant either App branch-protection bypass.
- **App token/key issue:** revoke/rotate the App private key through GitHub,
  update the protected environment secrets by name, close suspect bot branches,
  and audit workflow logs. Do not paste key or token values into issues, PRs, or
  docs.
- **Workflow disabled, App installation removed, or protected environment
  unavailable:** use the manual deterministic tooling below and open a normal
  maintainer-reviewed PR until the automation environment is restored.

## Preferred deterministic tooling

Use the tap-owned Ruby helper before opening a formula bump PR. Keep metadata and
any downloads outside tracked repository paths, such as under `mktemp -d` or
`$RUNNER_TEMP`:

```sh
metadata_dir="$(mktemp -d)"
trap 'rm -rf "$metadata_dir"' EXIT
ruby scripts/pm_formula_bump.rb plan \
  --tag vX.Y.Z \
  --metadata-out "$metadata_dir/pm-formula-metadata.json"
ruby scripts/pm_formula_bump.rb apply \
  --metadata "$metadata_dir/pm-formula-metadata.json" \
  --formula Formula/pm.rb \
  --readme README.md \
  --write
ruby scripts/pm_formula_bump.rb check \
  --metadata "$metadata_dir/pm-formula-metadata.json" \
  --formula Formula/pm.rb \
  --readme README.md
```

The helper accepts only stable tags like `v1.2.3`, keeps the upstream repository
and source archive URL fixed to `polymetrics-ai/cli`, resolves the tag commit
from the GitHub tag ref and build date from that commit, hashes the immutable
source archive, updates `Formula/pm.rb` and the README trust metadata together,
and refuses downgrades, same-version metadata conflicts, and paths outside the
formula/README allowlist. `apply --write` also refuses unexpected tracked-file
changes outside those two generated files.

## 1. Confirm the upstream tag

1. Confirm the intended PM tag exists in `polymetrics-ai/cli` and is immutable
   for the release being packaged.
2. Record the release version, commit, and build date that the CLI repository
   supports through linker variables in `polymetrics.ai/internal/cli`.
3. Confirm the license boundary has not changed. If it has, update the Homebrew
   license expression and installed license metadata deliberately.

## 2. Update `Formula/pm.rb`

1. Change `url` to the immutable tag archive:
   `https://github.com/polymetrics-ai/cli/archive/refs/tags/vX.Y.Z.tar.gz`.
2. Compute and replace `sha256` from the downloaded tag archive.
3. Update linker variables for:
   - `polymetrics.ai/internal/cli.version`
   - `polymetrics.ai/internal/cli.commit`
   - `polymetrics.ai/internal/cli.buildDate`
4. Keep `CGO_ENABLED=0` and `GOTOOLCHAIN=local` unless the CLI repository has an
   explicitly reviewed reason to change the build boundary.
5. Keep `go` as a build-only dependency unless runtime dependencies are added and
   verified.
6. Ensure project license files and connector-definition license metadata still
   install from the correct paths.

## 3. Validate locally where possible

Run the Homebrew-supported checks from a clean checkout by tapping that
checkout, then validating the formula by name:

```sh
brew untap polymetrics-ai/tap || true
brew tap polymetrics-ai/tap "file://$PWD"
brew audit --new --strict --online --formula polymetrics-ai/tap/pm
brew style --formula polymetrics-ai/tap/pm
brew install --build-from-source polymetrics-ai/tap/pm
brew test polymetrics-ai/tap/pm
"$(brew --prefix pm)/bin/pm" version --json
"$(brew --prefix pm)/bin/pm" connectors inspect sample --json
brew uninstall --formula pm
brew untap polymetrics-ai/tap
```

If the local host does not prove every supported CI architecture, state that
limitation in the pull request and let the GitHub Actions matrix prove the rest.
The initial public-tap matrix is intentionally bounded to GitHub-hosted
`ubuntu-latest` (x64 Linux), `macos-15` (arm64 macOS), and `macos-15-intel`
(Intel macOS). Do not use Polymetrics self-hosted website runners for tap
validation, and do not remove checks to hide an unproven architecture.

## 4. Pull request and rollback

1. Open one focused PR that follows the accepted contribution policy in
   [`../SECURITY.md`](../SECURITY.md), describing the formula update and
   validation results.
2. Reference the relevant CLI release/process issue. Use closing keywords only
   for work fully delivered by the PR.
3. Wait for `.github/workflows/homebrew.yml` to pass before requesting merge.
4. Never merge from an agent lane unless explicitly instructed.
5. Roll back a bad bump by reverting the formula commit or opening a new PR that
   restores the last known-good immutable tag, checksum, and linker metadata.

## 5. Optional future bottle or provenance work

Bottles, signing, notarization, provenance attestations, and release-asset
changes are separate distribution decisions. They require separate approval,
secrets/permission review, and documentation before adding release-write
permissions or publication workflows to this tap.
