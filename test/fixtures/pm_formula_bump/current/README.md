# Polymetrics Homebrew Tap

Homebrew tap for the public Polymetrics `pm` command-line interface.

## Install

Install from this tap with the fully qualified formula name:

```sh
brew install polymetrics-ai/tap/pm
```

Do not rely on short-name installation until you have explicitly decided to trust
and tap this repository and verified which formula name Homebrew resolves.

## Trust and verification

This tap builds PM from the immutable upstream source archive for the formula
version, not from a moving branch or unchecked release asset. The `pm` formula
pins:

- source: `https://github.com/polymetrics-ai/cli/archive/refs/tags/v0.1.1.tar.gz`
- SHA-256: `09e94f2a6524d881aed328c30b27f9ff39e40975fea67b4a540ea76a8ef4fa00`
- build metadata embedded in `pm version --json`: version `0.1.1`, commit
  `4a30b802d5b9ab7188181eacac1812cceed0e543`, and build date
  `2026-07-28T12:29:42Z`

After installation, verify the build you received:

```sh
pm version --json
pm connectors inspect sample --json
brew test polymetrics-ai/tap/pm
```

The formula also installs project licensing metadata under Homebrew's formula
share directory, including the MIT boundary for embedded connector definitions.

## Source-build security boundary

Homebrew source builds normally avoid the browser-quarantined, unsigned-Mach-O
path that applies when a user downloads and opens an unsigned binary directly in
a browser. This is **not** Apple Developer ID signing, notarization, or Gatekeeper
attestation. Treat this tap as source-build distribution with pinned source and
checksums; review the formula, upstream tag, and repository trust boundary before
installing.

This tap does not publish casks, bottles, Apple signing credentials, or direct
release-asset installers.

## Upgrade

When this tap is updated for a newer PM release:

```sh
brew update
brew upgrade polymetrics-ai/tap/pm
pm version --json
```

Homebrew may also upgrade the formula automatically as part of normal `brew
upgrade` usage.

## Uninstall

```sh
brew uninstall polymetrics-ai/tap/pm
```

If you tapped the repository explicitly and no longer need it:

```sh
brew untap polymetrics-ai/tap
```

## Maintainers

- Formula source of truth: [`Formula/pm.rb`](Formula/pm.rb)
- Homebrew validation workflow: [`.github/workflows/homebrew.yml`](.github/workflows/homebrew.yml)
- Contribution and vulnerability policy: [`SECURITY.md`](SECURITY.md)
- Future formula bump procedure: [`docs/formula-bump.md`](docs/formula-bump.md)

The validation workflow uses only GitHub-hosted public-repository labels:
`ubuntu-latest` (x64 Linux), `macos-15` (arm64 macOS), and `macos-15-intel`
(Intel macOS). It does not use Polymetrics self-hosted website runners.

Keep releases immutable: update the formula only to fixed PM tags with checked
source checksums and matching embedded build metadata.
