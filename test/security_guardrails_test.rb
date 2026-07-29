# frozen_string_literal: true

require "minitest/autorun"
require "yaml"

class SecurityGuardrailsTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__).freeze
  FORMULA = File.join(ROOT, "Formula/pm.rb").freeze
  README = File.join(ROOT, "README.md").freeze
  AUTH_WORKFLOW = File.join(ROOT, ".github/workflows/pull-request-authorization.yml").freeze
  HOMEBREW_WORKFLOW = File.join(ROOT, ".github/workflows/homebrew.yml").freeze
  PM_RELEASE_DRY_RUN_WORKFLOW = File.join(ROOT, ".github/workflows/pm-release-dry-run.yml").freeze
  CODEOWNERS = File.join(ROOT, ".github/CODEOWNERS").freeze
  AUTHORIZATION_CONCURRENCY_GROUP = 'pull-request-authorization-\$\{\{ github\.event\.pull_request\.number \}\}'
  HOMEBREW_CONCURRENCY_GROUP = 'homebrew-validation-\$\{\{ github\.ref \}\}'
  PM_RELEASE_DRY_RUN_CONCURRENCY_GROUP = 'pm-release-dry-run-\$\{\{ inputs\.version \}\}'

  FORBIDDEN_WORKFLOW_WRITE_PERMISSIONS = %w[
    actions
    attestations
    checks
    contents
    deployments
    id-token
    issues
    packages
    pages
    security-events
    secrets
    statuses
  ].freeze

  ATTACKER_CONTROLLED_CONTEXTS = %w[
    github.event.pull_request.title
    github.event.pull_request.body
    github.event.pull_request.head.ref
    github.event.pull_request.head.label
    github.head_ref
  ].freeze

  def setup
    @auth_text = File.read(AUTH_WORKFLOW)
    @homebrew_text = File.read(HOMEBREW_WORKFLOW)
    @dry_run_text = File.read(PM_RELEASE_DRY_RUN_WORKFLOW)
    @formula_text = File.read(FORMULA)
    @readme_text = File.read(README)
  end

  def test_workflows_are_valid_yaml
    [AUTH_WORKFLOW, HOMEBREW_WORKFLOW, PM_RELEASE_DRY_RUN_WORKFLOW].each do |workflow|
      assert_kind_of Hash, YAML.safe_load_file(workflow, aliases: false), "#{workflow} should parse as YAML"
    end
  end

  def test_codeowners_assigns_everything_to_captain_for_visibility
    assert_equal "* @karthik-sivadas\n", File.read(CODEOWNERS)
  end

  def test_authorization_workflow_uses_pull_request_target_without_checkout
    assert_match(/^\s+pull_request_target:/, @auth_text)
    refute_match(%r{uses:\s*actions/checkout@}i, @auth_text)
    refute_match(/\bgit\s+checkout\b/i, @auth_text)
  end

  def test_authorization_workflow_has_stable_check_and_bounded_execution
    assert_includes @auth_text, "name: PR author authorization"
    assert_match(/^    timeout-minutes: 5$/, @auth_text)
    assert_concurrency_group @auth_text, AUTHORIZATION_CONCURRENCY_GROUP
  end

  def test_authorization_workflow_least_privilege_permissions
    assert_match(/^permissions:\n  contents: read\n  pull-requests: write\n/m, @auth_text)

    FORBIDDEN_WORKFLOW_WRITE_PERMISSIONS.each do |permission|
      refute_match(/^\s+#{Regexp.escape(permission)}:\s*write\b/, @auth_text,
                   "#{permission}: write must not be granted")
    end
  end

  def test_authorization_workflow_accepts_only_captain_authored_pull_requests
    assert_includes @auth_text, "github.event.pull_request.user.login == 'karthik-sivadas'"
    assert_includes @auth_text, "github.event.pull_request.user.login != 'karthik-sivadas'"
    assert_includes @auth_text, 'run: echo "Pull request author is authorized."'
  end

  def test_unauthorized_pull_requests_are_commented_closed_and_cannot_satisfy_check
    assert_includes @auth_text, "Comment on and close unauthorized pull requests"
    assert_includes @auth_text, 'if ! gh api "repos/polymetrics-ai/homebrew-tap/pulls/${PR_NUMBER}/reviews"'
    assert_includes @auth_text, "--field event=COMMENT"
    assert_includes @auth_text, "pulls/${PR_NUMBER}"
    assert_includes @auth_text, "--field state=closed"
    assert_includes @auth_text, "Unable to add unauthorized pull request review comment; closing will continue."
    assert_includes @auth_text, "exit 1"
  end

  def test_authorization_shell_does_not_consume_attacker_controlled_text
    ATTACKER_CONTROLLED_CONTEXTS.each do |context|
      refute_includes @auth_text, context
    end

    assert_match(/case "\$\{PR_NUMBER\}" in\n\s+''\|\*\[!0-9\]\*\)/, @auth_text)
  end

  def test_homebrew_validation_runs_only_on_trusted_repository_pushes
    assert_match(/^  push:$/, @homebrew_text)
    refute_match(/^\s+pull_request:/, @homebrew_text)
    refute_match(/^\s+pull_request_target:/, @homebrew_text)
    refute_includes @homebrew_text, "github.event.pull_request"
    refute_includes @homebrew_text, "github.event_name"
    assert_includes @homebrew_text, "ruby test/security_guardrails_test.rb"
    assert_includes @homebrew_text, "ruby test/pm_release_verifier_test.rb"
    assert_includes @homebrew_text, "PM source build (${{ matrix.label }})"
    assert_match(/^    timeout-minutes: 60$/, @homebrew_text)
    assert_concurrency_group @homebrew_text, HOMEBREW_CONCURRENCY_GROUP
  end

  def test_pm_release_dry_run_workflow_is_manual_read_only_and_non_mutating
    assert_includes @dry_run_text, "name: PM release dry-run verification"
    assert_match(/^  workflow_dispatch:$/, @dry_run_text)
    refute_match(/^\s+push:/, @dry_run_text)
    refute_match(/^\s+pull_request:/, @dry_run_text)
    refute_match(/^\s+pull_request_target:/, @dry_run_text)
    assert_match(/^permissions:\n  attestations: read\n  contents: read\n/m, @dry_run_text)
    assert_match(/^    permissions:\n      attestations: read\n      contents: read\n/m, @dry_run_text)
    assert_concurrency_group @dry_run_text, PM_RELEASE_DRY_RUN_CONCURRENCY_GROUP, cancel_in_progress: false

    (FORBIDDEN_WORKFLOW_WRITE_PERMISSIONS + %w[pull-requests]).each do |permission|
      refute_match(/^\s+#{Regexp.escape(permission)}:\s*write\b/, @dry_run_text,
                   "#{permission}: write must not be granted")
    end

    %w[git\ push git\ commit gh\ pr gh\ release gh\ secret gh\ variable].each do |forbidden|
      refute_match(/#{forbidden}/, @dry_run_text)
    end
    assert_includes @dry_run_text, "ruby scripts/pm_release_verifier.rb verify"
    assert_match(%r{uses:\s+sigstore/cosign-installer@d7543c93d881b35a8faa02e8e3605f69b7a1ce62\b}, @dry_run_text)
    assert_includes @dry_run_text, "cosign-release: v2.6.4"
    assert_includes @dry_run_text, "gh attestation verify --help"
    %w[
      --cert-identity
      --cert-oidc-issuer
      --deny-self-hosted-runners
      --format
      --limit
      --predicate-type
      --source-digest
      --source-ref
    ].each do |flag|
      assert_includes @dry_run_text, flag
    end
    refute_includes @dry_run_text, "--signer-workflow"
    assert_includes @dry_run_text, "Dry-run verifier mutated tracked repository files."
  end

  def test_pm_release_dry_run_shell_uses_environment_for_untrusted_inputs
    %w[dispatch_schema source_repo version release_id source_run_id target_commitish_policy].each do |input|
      assert_includes @dry_run_text, "${{ inputs.#{input} }}"
    end

    run_blocks = @dry_run_text.scan(/^\s+run: \|\n(?<body>(?:^\s{10}.*\n?)+)/).flatten.join("\n")
    refute_includes run_blocks, "${{ inputs."
    assert_includes run_blocks, '--version "${PM_VERSION}"'
    assert_includes run_blocks, '--release-id "${PM_RELEASE_ID}"'
  end

  def test_all_referenced_actions_are_pinned_to_full_commit_shas
    workflow_text = [@auth_text, @homebrew_text, @dry_run_text].join("\n")
    uses_lines = workflow_text.lines.grep(/^\s*uses:/)

    refute_empty uses_lines
    uses_lines.each do |line|
      assert_match(/uses:\s+[^\s@]+@[0-9a-f]{40}(?:\s+#.*)?$/i, line)
    end

    assert_match(%r{uses:\s+actions/checkout@11d5960a326750d5838078e36cf38b85af677262\b}, @homebrew_text)
  end

  def test_readme_trust_metadata_matches_pm_formula
    assert_equal pm_formula_metadata, readme_trust_metadata
  end

  private

  def pm_formula_metadata
    {
      source:     capture(@formula_text, /^\s*url "([^"]+)"$/, "formula source URL"),
      sha256:     capture(@formula_text, /^\s*sha256 "([0-9a-f]{64})"$/, "formula SHA-256"),
      version:    capture(@formula_text, %r{-X polymetrics\.ai/internal/cli\.version=([^\s]+)},
                          "formula version metadata"),
      commit:     capture(@formula_text, %r{-X polymetrics\.ai/internal/cli\.commit=([0-9a-f]{40})},
                          "formula commit metadata"),
      build_date: capture(@formula_text, %r{-X polymetrics\.ai/internal/cli\.buildDate=([^\s]+)},
                          "formula build date metadata"),
    }
  end

  def readme_trust_metadata
    {
      source:     capture(@readme_text, /^- source: `([^`]+)`$/, "README source URL"),
      sha256:     capture(@readme_text, /^- SHA-256: `([0-9a-f]{64})`$/, "README SHA-256"),
      version:    capture(@readme_text, /version `([^`]+)`, commit\s+`[0-9a-f]{40}`, and build date/,
                          "README version metadata"),
      commit:     capture(@readme_text, /version `[^`]+`, commit\s+`([0-9a-f]{40})`, and build date/,
                          "README commit metadata"),
      build_date: capture(@readme_text, /and build date\s+`([^`]+)`/, "README build date metadata"),
    }
  end

  def capture(text, pattern, description)
    match = text.match(pattern)
    refute_nil match, "#{description} should be present"
    match[1]
  end

  def assert_concurrency_group(workflow_text, group_pattern, cancel_in_progress: true)
    assert_match(/^concurrency:\n  group: "#{group_pattern}"\n  cancel-in-progress: #{cancel_in_progress}$/m, workflow_text)
  end
end
