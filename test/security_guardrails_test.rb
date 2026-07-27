# frozen_string_literal: true

require "minitest/autorun"
require "yaml"

class SecurityGuardrailsTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  AUTH_WORKFLOW = File.join(ROOT, ".github/workflows/pull-request-authorization.yml")
  HOMEBREW_WORKFLOW = File.join(ROOT, ".github/workflows/homebrew.yml")
  CODEOWNERS = File.join(ROOT, ".github/CODEOWNERS")

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

  def setup
    @auth_text = File.read(AUTH_WORKFLOW)
    @homebrew_text = File.read(HOMEBREW_WORKFLOW)
  end

  def test_workflows_are_valid_yaml
    [AUTH_WORKFLOW, HOMEBREW_WORKFLOW].each do |workflow|
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
    assert_match(/^concurrency:\n  group: "pull-request-authorization-\$\{\{ github\.event\.pull_request\.number \}\}"\n  cancel-in-progress: true$/m, @auth_text)
  end

  def test_authorization_workflow_least_privilege_permissions
    assert_match(/^permissions:\n  contents: read\n  pull-requests: write\n/m, @auth_text)

    FORBIDDEN_WORKFLOW_WRITE_PERMISSIONS.each do |permission|
      refute_match(/^\s+#{Regexp.escape(permission)}:\s*write\b/, @auth_text, "#{permission}: write must not be granted")
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
    attacker_controlled_contexts = %w[
      github.event.pull_request.title
      github.event.pull_request.body
      github.event.pull_request.head.ref
      github.event.pull_request.head.label
      github.head_ref
    ]

    attacker_controlled_contexts.each do |context|
      refute_includes @auth_text, context
    end

    assert_match(/case "\$\{PR_NUMBER\}" in\n\s+''\|\*\[!0-9\]\*\)/, @auth_text)
  end

  def test_homebrew_validation_skips_unauthorized_pull_request_code_execution_only
    assert_includes @homebrew_text,
                    "github.event_name != 'pull_request' || github.event.pull_request.user.login == 'karthik-sivadas'"
    assert_includes @homebrew_text, "Security guardrails"
    assert_includes @homebrew_text, "ruby test/security_guardrails_test.rb"
    assert_includes @homebrew_text, "PM source build (${{ matrix.label }})"
    assert_match(/^    timeout-minutes: 60$/, @homebrew_text)
    assert_match(/^concurrency:\n  group: "homebrew-validation-\$\{\{ github\.event\.pull_request\.number \|\| github\.ref \}\}"\n  cancel-in-progress: true$/m, @homebrew_text)
  end

  def test_all_referenced_actions_are_pinned_to_full_commit_shas
    workflow_text = [@auth_text, @homebrew_text].join("\n")
    uses_lines = workflow_text.lines.grep(/^\s*uses:/)

    refute_empty uses_lines
    uses_lines.each do |line|
      assert_match(%r{uses:\s+[^\s@]+@[0-9a-f]{40}(?:\s+#.*)?$}i, line)
    end

    assert_match(%r{uses:\s+actions/checkout@11d5960a326750d5838078e36cf38b85af677262\b}, @homebrew_text)
  end
end
