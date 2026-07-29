# frozen_string_literal: true

require "json"
require "minitest/autorun"
require "open3"
require "tmpdir"
require "yaml"

class SecurityGuardrailsTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__).freeze
  FORMULA = File.join(ROOT, "Formula/pm.rb").freeze
  README = File.join(ROOT, "README.md").freeze
  AUTH_WORKFLOW = File.join(ROOT, ".github/workflows/pull-request-authorization.yml").freeze
  HOMEBREW_WORKFLOW = File.join(ROOT, ".github/workflows/homebrew.yml").freeze
  PM_RELEASE_DRY_RUN_WORKFLOW = File.join(ROOT, ".github/workflows/pm-release-dry-run.yml").freeze
  PM_FORMULA_UPDATE_WORKFLOW = File.join(ROOT, ".github/workflows/pm-formula-update.yml").freeze
  CODEOWNERS = File.join(ROOT, ".github/CODEOWNERS").freeze
  AUTHORIZATION_CONCURRENCY_GROUP = 'pull-request-authorization-\$\{\{ github\.event\.pull_request\.number \}\}'
  HOMEBREW_CONCURRENCY_GROUP = 'homebrew-validation-\$\{\{ github\.ref \}\}'
  PM_RELEASE_DRY_RUN_CONCURRENCY_GROUP = 'pm-release-dry-run-\$\{\{ inputs\.version \}\}'
  PM_FORMULA_UPDATE_CONCURRENCY_GROUP = 'pm-formula-update-\$\{\{ inputs\.tag \}\}'

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
    @formula_update_text = File.read(PM_FORMULA_UPDATE_WORKFLOW)
    @formula_text = File.read(FORMULA)
    @readme_text = File.read(README)
  end

  def test_workflows_are_valid_yaml
    [AUTH_WORKFLOW, HOMEBREW_WORKFLOW, PM_RELEASE_DRY_RUN_WORKFLOW, PM_FORMULA_UPDATE_WORKFLOW].each do |workflow|
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

  def test_authorization_workflow_accepts_captain_or_exact_homebrew_bot_route_only
    assert_includes @auth_text, 'CAPTAIN_LOGIN = "karthik-sivadas"'
    assert_includes @auth_text, 'BOT_LOGIN = "pm-homebrew-pr-bot[bot]"'
    assert_includes @auth_text, 'BOT_BRANCH_PATTERN = /\Apm-release\/v'
    assert_includes @auth_text, 'BOT_CHANGED_FILES = ["Formula/pm.rb", "README.md"].freeze'
    assert_includes @auth_text, 'head repository must be the same repository'
    assert_includes @auth_text, 'fork pull requests are not allowed for the automation route'
    assert_includes @auth_text, 'changed files must be exactly'
  end

  def test_unauthorized_pull_requests_are_commented_closed_and_cannot_satisfy_check
    assert_includes @auth_text, "This pull request did not satisfy the authorization policy"
    refute_includes @auth_text, "cat <<COMMENT"
    assert_includes @auth_text, "body=\"$(printf '%s\\n\\n%s\\n\\n%s %s\\n\\n%s\\n'"
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
    assert_includes @homebrew_text, "ruby test/pm_formula_pr_test.rb"
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

  def test_pm_formula_update_workflow_is_default_branch_dispatch_with_read_only_github_token
    assert_includes @formula_update_text, "name: PM formula update"
    assert_match(/^  workflow_dispatch:$/, @formula_update_text)
    refute_match(/^\s+push:/, @formula_update_text)
    refute_match(/^\s+pull_request:/, @formula_update_text)
    refute_match(/^\s+pull_request_target:/, @formula_update_text)
    assert_match(/^permissions:\n  attestations: read\n  contents: read\n/m, @formula_update_text)
    assert_match(/^    permissions:\n      attestations: read\n      contents: read\n/m, @formula_update_text)
    assert_concurrency_group @formula_update_text, PM_FORMULA_UPDATE_CONCURRENCY_GROUP, cancel_in_progress: false
    assert_includes @formula_update_text, "github.ref == 'refs/heads/main'"
    assert_includes @formula_update_text, "github.repository == 'polymetrics-ai/homebrew-tap'"

    (FORBIDDEN_WORKFLOW_WRITE_PERMISSIONS + %w[pull-requests]).each do |permission|
      refute_match(/^\s+#{Regexp.escape(permission)}:\s*write\b/, @formula_update_text,
                   "#{permission}: write must not be granted to GITHUB_TOKEN")
    end
  end

  def test_pm_formula_update_mints_pr_app_token_only_in_prepare_job_environment
    validate_section, prepare_and_after = @formula_update_text.split(/^  prepare-pr:\n/, 2)
    refute_nil prepare_and_after
    prepare_section = prepare_and_after.split(/^  audit-summary:\n/, 2).first

    refute_includes validate_section, "PM_HOMEBREW_PR_APP_ID"
    refute_includes validate_section, "PM_HOMEBREW_PR_PRIVATE_KEY"
    assert_includes prepare_section, "environment: homebrew-formula-automation"
    assert_match(/^    permissions:\n      contents: read\n/m, prepare_section)
    assert_includes prepare_section, "Mint pm-homebrew-pr-bot installation token"
    assert_includes prepare_section, "PM_HOMEBREW_PR_APP_ID: ${{ secrets.PM_HOMEBREW_PR_APP_ID }}"
    assert_includes prepare_section, "PM_HOMEBREW_PR_PRIVATE_KEY: ${{ secrets.PM_HOMEBREW_PR_PRIVATE_KEY }}"
    assert_includes prepare_section, 'app["slug"] == "pm-homebrew-pr-bot"'
    assert_includes prepare_section, '"permissions" => { "contents" => "write", "pull_requests" => "write" }'
    assert_includes prepare_section, 'allowed_permission_keys = ["contents", "metadata", "pull_requests"]'
    assert_includes prepare_section, "PM_BRANCH_PUSH_TOKEN: ${{ steps.app-token.outputs.token }}"
    assert_includes prepare_section, "GH_TOKEN: ${{ steps.app-token.outputs.token }}"
    assert_includes prepare_section, "persist-credentials: false"
    assert_includes prepare_section, "ruby scripts/pm_formula_pr.rb prepare"
    assert_includes prepare_section, "inputs.dispatch_schema == 'pm-homebrew-formula/v1'"
    assert_includes prepare_section, "needs.validate-release.outputs.dispatch_schema == 'pm-homebrew-formula/v1'"
    assert_includes prepare_section, "inputs.dry_run == 'false'"
    refute_includes @formula_update_text, "PERSONAL_ACCESS_TOKEN"
    refute_includes @formula_update_text, " PAT"
  end

  def test_pm_formula_update_shell_uses_environment_for_untrusted_inputs
    %w[dispatch_schema source_repo tag release_id source_run_id target_commitish_policy dry_run].each do |input|
      assert_includes @formula_update_text, "${{ inputs.#{input} }}"
    end

    run_blocks = @formula_update_text.scan(/^\s+run: \|\n(?<body>(?:^\s{10}.*\n?)+)/).flatten.join("\n")
    refute_includes run_blocks, "${{ inputs."
    assert_includes run_blocks, '--tag "${PM_TAG}"'
    assert_includes run_blocks, '--release-id "${PM_RELEASE_ID}"'
  end

  def test_authorization_inline_policy_allows_and_denies_expected_routes
    allowed_bot = authorization_decision(
      pr_json(login: "pm-homebrew-pr-bot[bot]", type: "Bot", head_ref: "pm-release/v1.2.3"),
      file_json("Formula/pm.rb"),
      file_json("README.md"),
    )
    assert allowed_bot.fetch("authorized"), allowed_bot.inspect
    assert_equal "pm-homebrew-pr-bot", allowed_bot.fetch("route")

    allowed_captain = authorization_decision(pr_json(login: "karthik-sivadas"), file_json(".github/workflows/anything.yml"))
    assert allowed_captain.fetch("authorized"), allowed_captain.inspect
    assert_equal "captain", allowed_captain.fetch("route")

    deny_fork = authorization_decision(
      pr_json(login: "pm-homebrew-pr-bot[bot]", type: "Bot", head_repo: "attacker/homebrew-tap", fork: true, head_ref: "pm-release/v1.2.3"),
      file_json("Formula/pm.rb"),
      file_json("README.md"),
    )
    refute deny_fork.fetch("authorized")
    assert_match(/head repository must be the same repository|fork pull requests are not allowed/, deny_fork.fetch("reason"))

    deny_bad_branch = authorization_decision(
      pr_json(login: "pm-homebrew-pr-bot[bot]", type: "Bot", head_ref: "pm-release/v1.2.3-rc.1"),
      file_json("Formula/pm.rb"),
      file_json("README.md"),
    )
    refute deny_bad_branch.fetch("authorized")
    assert_match(/strict stable semver/, deny_bad_branch.fetch("reason"))

    deny_workflow = authorization_decision(
      pr_json(login: "pm-homebrew-pr-bot[bot]", type: "Bot", head_ref: "pm-release/v1.2.3"),
      file_json("Formula/pm.rb"),
      file_json("README.md"),
      file_json(".github/workflows/homebrew.yml"),
    )
    refute deny_workflow.fetch("authorized")
    assert_match(/changed files must be exactly|\.github paths/, deny_workflow.fetch("reason"))

    deny_public = authorization_decision(pr_json(login: "contributor"), file_json("Formula/pm.rb"), file_json("README.md"))
    refute deny_public.fetch("authorized")
    assert_match(/not an approved maintainer or exact Homebrew automation bot/, deny_public.fetch("reason"))
  end

  def test_all_referenced_actions_are_pinned_to_full_commit_shas
    workflow_text = [@auth_text, @homebrew_text, @dry_run_text, @formula_update_text].join("\n")
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

  def authorization_decision(pr, *files)
    Dir.mktmpdir("pm-pr-authorization-") do |dir|
      script = File.join(dir, "authorize.rb")
      pr_path = File.join(dir, "pr.json")
      files_path = File.join(dir, "files.json")
      output_path = File.join(dir, "decision.json")
      File.write(script, authorization_script)
      File.write(pr_path, JSON.generate(pr))
      File.write(files_path, JSON.generate(files))
      stdout, _stderr, _status = Open3.capture3("ruby", script, pr_path, files_path)
      File.write(output_path, stdout)
      JSON.parse(File.read(output_path))
    end
  end

  def authorization_script
    match = @auth_text.match(/# BEGIN PM PR AUTHORIZER\n(?<script>.*?)^\s*# END PM PR AUTHORIZER/m)
    refute_nil match, "inline authorization script should be extractable for fixture tests"
    match[:script].lines.map { |line| line.sub(/^          /, "") }.join
  end

  def pr_json(login:, type: "User", base_repo: "polymetrics-ai/homebrew-tap", base_ref: "main",
              head_repo: "polymetrics-ai/homebrew-tap", head_ref: "feature", fork: false)
    {
      "user" => { "login" => login, "type" => type },
      "base" => { "ref" => base_ref, "repo" => { "full_name" => base_repo } },
      "head" => { "ref" => head_ref, "repo" => { "full_name" => head_repo, "fork" => fork } },
    }
  end

  def file_json(filename, status: "modified")
    { "filename" => filename, "status" => status }
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
