# Security policy

## Accepted contribution policy

This public Homebrew tap remains readable and installable through Homebrew, but
it does not accept public pull-request contributions from arbitrary authors.

Broad pull requests authored by `karthik-sivadas` are accepted for review and
merge. The `pm-homebrew-pr-bot[bot]` automation route is limited to
same-repository `pm-release/vX.Y.Z` branches that modify only `Formula/pm.rb`
and `README.md`. GitHub cannot prevent external users from opening pull
requests against a public repository; the repository guardrail closes every
other pull request without checking out or executing contributor code.

All changes to `main` must go through a pull request, satisfy the required
Homebrew source-build matrix, and be merged by the maintainer. Do not send
credentials, secrets, private keys, signing material, or personal data in
issues, pull requests, comments, or workflow logs.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting flow for this repository:

1. Open the repository's **Security** tab on GitHub.
2. Choose **Report a vulnerability**.
3. Provide the minimum details needed to reproduce and assess the issue.

This route keeps the report private to repository maintainers while it is triaged. Do not publish exploit details publicly before a fix or mitigation is available.
