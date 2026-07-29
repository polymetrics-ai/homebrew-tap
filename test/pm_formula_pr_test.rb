# frozen_string_literal: true

require "fileutils"
require "json"
require "minitest/autorun"
require "open3"
require "tmpdir"

require_relative "../scripts/pm_formula_pr"

class PMFormulaPRTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  FIXTURES = File.join(ROOT, "test/fixtures/pm_formula_bump")
  CURRENT_METADATA = JSON.parse(File.read(File.join(FIXTURES, "v0.1.1-metadata.json"))).freeze
  PREVIOUS_METADATA = PMFormulaBump.build_metadata(
    tag: "v0.1.0",
    source_sha256: "c947c513a2e192b5b730070ef2052e14eadacd199edc4d3051943a65c27050ea",
    commit: "6de947ca89946a461b5c4c5b0daadf3a0f0f6ad6",
    build_date: "2026-07-27T11:29:34Z",
  ).freeze
  NEXT_METADATA = PMFormulaBump.build_metadata(
    tag: "v0.1.2",
    source_sha256: "1" * 64,
    commit: "2" * 40,
    build_date: "2026-07-29T00:00:00Z",
  ).freeze

  def setup
    @tmpdirs = []
  end

  def teardown
    @tmpdirs.each { |dir| FileUtils.rm_rf(dir) }
  end

  def test_new_branch_creates_one_deterministic_branch_and_pr_without_touching_main
    with_work_repo("current") do |work, _remote|
      prs = FakePullRequests.new
      main_sha = git(work, "rev-parse", "origin/main").strip

      result = prepare(work, NEXT_METADATA, prs)

      assert_equal "branch-absent", result.fetch("state")
      assert_equal "created", result.fetch("pr_action")
      assert_equal "pm-release/v0.1.2", result.fetch("branch")
      assert_equal 1, prs.created.length
      assert_equal main_sha, git(work, "rev-parse", "origin/main").strip
      assert_equal result.fetch("commit"), remote_head(work, "pm-release/v0.1.2")
      assert_equal PMFormulaPR::ALLOWED_CHANGED_PATHS.sort,
                   git(work, "diff", "--name-only", "origin/main..#{result.fetch("commit")}").lines.map(&:chomp).sort
      assert_equal [], remote_branch_names(work).grep("main") - ["main"]
    end
  end

  def test_git_and_pull_request_clients_require_explicit_app_token
    git_error = assert_raises(PMFormulaPR::Error) do
      PMFormulaPR::Git.new(root: ROOT, push_token: "")
    end
    pr_error = assert_raises(PMFormulaPR::Error) do
      PMFormulaPR::PullRequestClient.new(token: "")
    end

    assert_match(/PM_BRANCH_PUSH_TOKEN is required/, git_error.message)
    assert_match(/PM_BRANCH_PUSH_TOKEN is required/, pr_error.message)
  end

  def test_clients_pass_app_token_without_ambient_github_token_fallback
    git_client = PMFormulaPR::Git.new(root: ROOT, push_token: "app-token")
    pull_requests = PMFormulaPR::PullRequestClient.new(token: "app-token")

    git_env = git_client.push_env
    gh_env = pull_requests.send(:gh_env)

    assert_equal "AUTHORIZATION: basic #{Base64.strict_encode64("x-access-token:app-token")}",
                 git_env.fetch("GIT_CONFIG_VALUE_0")
    assert_equal "", git_env.fetch("GIT_CONFIG_VALUE_1")
    assert_equal "app-token", gh_env.fetch("GH_TOKEN")
    assert_nil gh_env.fetch("GITHUB_TOKEN")
  end

  def test_duplicate_dispatch_reuses_exact_bot_branch_and_updates_existing_pr
    with_work_repo("current") do |work, _remote|
      prs = FakePullRequests.new
      first = prepare(work, NEXT_METADATA, prs)
      second = prepare(work, NEXT_METADATA, prs)

      assert_equal "branch-absent", first.fetch("state")
      assert_equal "branch-current", second.fetch("state")
      assert_equal first.fetch("commit"), second.fetch("commit")
      assert_equal 1, prs.created.length
      assert_equal 1, prs.updated.length
      assert_equal [1], prs.all.map { |pr| pr.fetch("number") }
    end
  end

  def test_already_current_formula_is_noop_and_does_not_create_remote_branch_or_pr
    with_work_repo("current") do |work, _remote|
      prs = FakePullRequests.new
      result = prepare(work, CURRENT_METADATA, prs)

      assert_equal "already-current", result.fetch("state")
      assert_equal false, result.fetch("mutated")
      assert_nil remote_head(work, "pm-release/v0.1.1")
      assert_empty prs.created
      assert_empty prs.updated
    end
  end

  def test_same_version_metadata_conflict_is_refused_without_branch_or_pr_mutation
    with_work_repo("current") do |work, _remote|
      conflict_metadata = CURRENT_METADATA.merge("source_sha256" => "a" * 64)
      prs = FakePullRequests.new

      error = assert_raises(PMFormulaPR::Error) { prepare(work, conflict_metadata, prs) }

      assert_match(/same-version Formula\/pm\.rb drift/, error.message)
      assert_nil remote_head(work, "pm-release/v0.1.1")
      assert_empty prs.created
      assert_empty prs.updated
    end
  end

  def test_newer_formula_is_noop_and_does_not_create_remote_branch_or_pr
    with_work_repo("current") do |work, _remote|
      prs = FakePullRequests.new
      result = prepare(work, PREVIOUS_METADATA, prs)

      assert_equal "newer-formula", result.fetch("state")
      assert_equal false, result.fetch("mutated")
      assert_nil remote_head(work, "pm-release/v0.1.0")
      assert_empty prs.created
      assert_empty prs.updated
    end
  end

  def test_stale_bot_owned_deterministic_branch_is_force_with_lease_converged
    with_work_repo("current") do |work, _remote|
      branch = PMFormulaPR.branch_for(NEXT_METADATA)
      stale_sha = create_formula_branch(work, branch, NEXT_METADATA, bot: true)
      advance_remote_main(work)
      prs = FakePullRequests.new

      result = prepare(work, NEXT_METADATA, prs)

      assert_equal "branch-stale-bot", result.fetch("state")
      refute_equal stale_sha, result.fetch("commit")
      assert_equal result.fetch("commit"), remote_head(work, branch)
      assert_equal 1, prs.created.length
    end
  end

  def test_bot_authored_branch_with_divergent_formula_content_is_refused
    with_work_repo("current") do |work, _remote|
      divergent_metadata = NEXT_METADATA.merge("source_sha256" => "3" * 64)
      branch = PMFormulaPR.branch_for(NEXT_METADATA)
      divergent_sha = create_formula_branch(work, branch, divergent_metadata, bot: true)
      prs = FakePullRequests.new

      error = assert_raises(PMFormulaPR::Error) { prepare(work, NEXT_METADATA, prs) }

      assert_match(/refusing to overwrite existing pm-release\/v0\.1\.2/, error.message)
      assert_equal divergent_sha, remote_head(work, branch)
      assert_empty prs.created
      assert_empty prs.updated
    end
  end

  def test_human_diverged_deterministic_branch_is_refused_without_branch_or_pr_mutation
    with_work_repo("current") do |work, _remote|
      branch = PMFormulaPR.branch_for(NEXT_METADATA)
      human_sha = create_formula_branch(work, branch, NEXT_METADATA, bot: false)
      prs = FakePullRequests.new

      error = assert_raises(PMFormulaPR::Error) { prepare(work, NEXT_METADATA, prs) }

      assert_match(/refusing to overwrite existing pm-release\/v0\.1\.2/, error.message)
      assert_equal human_sha, remote_head(work, branch)
      assert_empty prs.created
      assert_empty prs.updated
    end
  end

  def test_existing_open_pr_is_updated_not_duplicated
    with_work_repo("current") do |work, _remote|
      branch = PMFormulaPR.branch_for(NEXT_METADATA)
      existing_sha = create_formula_branch(work, branch, NEXT_METADATA, bot: true)
      prs = FakePullRequests.new([
        {
          "number" => 42,
          "html_url" => "https://github.com/polymetrics-ai/homebrew-tap/pull/42",
          "head" => { "ref" => branch },
          "base" => { "ref" => PMFormulaPR::BASE_BRANCH },
          "state" => "open",
          "title" => "old title",
          "body" => "old body",
          "user" => bot_pr_user,
        },
      ])

      result = prepare(work, NEXT_METADATA, prs)

      assert_equal "branch-current", result.fetch("state")
      assert_equal existing_sha, result.fetch("commit")
      assert_equal "updated", result.fetch("pr_action")
      assert_equal 42, result.fetch("pr_number")
      assert_empty prs.created
      assert_equal [42], prs.updated.map { |pr| pr.fetch("number") }
      assert_match(/verified the immutable upstream release evidence/, prs.all.first.fetch("body"))
    end
  end

  def test_human_authored_existing_open_pr_for_branch_is_refused
    with_work_repo("current") do |work, _remote|
      branch = PMFormulaPR.branch_for(NEXT_METADATA)
      existing_sha = create_formula_branch(work, branch, NEXT_METADATA, bot: true)
      prs = FakePullRequests.new([
        {
          "number" => 42,
          "html_url" => "https://github.com/polymetrics-ai/homebrew-tap/pull/42",
          "head" => { "ref" => branch },
          "base" => { "ref" => PMFormulaPR::BASE_BRANCH },
          "state" => "open",
          "title" => "old title",
          "body" => "old body",
          "user" => { "login" => "human-maintainer", "type" => "User" },
        },
      ])

      error = assert_raises(PMFormulaPR::Error) { prepare(work, NEXT_METADATA, prs) }

      assert_match(/PR author is not pm-homebrew-pr-bot\[bot\]/, error.message)
      assert_equal existing_sha, remote_head(work, branch)
      assert_empty prs.created
      assert_empty prs.updated
    end
  end

  def test_dry_run_schema_verification_is_refused_without_branch_or_pr_mutation
    with_work_repo("current") do |work, _remote|
      prs = FakePullRequests.new

      error = assert_raises(PMFormulaPR::Error) do
        prepare(
          work,
          NEXT_METADATA,
          prs,
          verification_overrides: { "dispatch_schema" => PMReleaseVerifier::DRY_RUN_DISPATCH_SCHEMA },
        )
      end

      assert_match(/verification dispatch_schema must be pm-homebrew-formula\/v1/, error.message)
      assert_nil remote_head(work, "pm-release/v0.1.2")
      assert_empty prs.created
      assert_empty prs.updated
    end
  end

  private

  class FakePullRequests
    attr_reader :created, :updated

    def initialize(prs = [])
      @prs = prs.map { |pr| deep_copy(pr) }
      @created = []
      @updated = []
      @next_number = [*@prs.map { |pr| pr.fetch("number") }, 0].max + 1
    end

    def all
      @prs
    end

    def open_pr_for_branch(branch, base_branch)
      matches = @prs.select do |pr|
        pr.fetch("state") == "open" && pr.dig("head", "ref") == branch && pr.dig("base", "ref") == base_branch
      end
      raise PMFormulaPR::Error, "multiple open PRs already exist for #{branch}" if matches.length > 1

      matches.first
    end

    def create_pr(branch:, base_branch:, title:, body:)
      pr = {
        "number" => @next_number,
        "html_url" => "https://github.com/polymetrics-ai/homebrew-tap/pull/#{@next_number}",
        "head" => { "ref" => branch },
        "base" => { "ref" => base_branch },
        "state" => "open",
        "title" => title,
        "body" => body,
        "user" => bot_pr_user,
      }
      @next_number += 1
      @prs << pr
      @created << pr
      pr
    end

    def update_pr(number:, title:, body:)
      pr = @prs.find { |candidate| candidate.fetch("number") == number }
      raise PMFormulaPR::Error, "missing PR #{number}" unless pr

      pr["title"] = title
      pr["body"] = body
      @updated << pr
      pr
    end

    private

    def deep_copy(object)
      JSON.parse(JSON.generate(object))
    end

    def bot_pr_user
      {
        "login" => PMFormulaPR::BOT_LOGIN,
        "type" => "Bot",
      }
    end
  end

  def prepare(work, metadata, prs, verification_overrides: {})
    metadata_path = metadata_file(metadata)
    verification_path = verification_file(metadata, verification_overrides: verification_overrides)
    git_client = PMFormulaPR::Git.new(root: work, push_token: "test-app-token")
    PMFormulaPR::Operations.new(root: work, git: git_client, pull_requests: prs).prepare(
      metadata_path: metadata_path,
      verification_path: verification_path,
      repository: PMFormulaPR::TARGET_REPOSITORY,
      remote: "origin",
      base_branch: PMFormulaPR::BASE_BRANCH,
    )
  end

  def bot_pr_user
    {
      "login" => PMFormulaPR::BOT_LOGIN,
      "type" => "Bot",
    }
  end

  def with_work_repo(fixture)
    dir = Dir.mktmpdir("pm-formula-pr-")
    @tmpdirs << dir
    seed = File.join(dir, "seed")
    remote = File.join(dir, "remote.git")
    work = File.join(dir, "work")

    FileUtils.mkdir_p(File.join(seed, "Formula"))
    FileUtils.cp(File.join(FIXTURES, fixture, "Formula/pm.rb"), File.join(seed, "Formula/pm.rb"))
    FileUtils.cp(File.join(FIXTURES, fixture, "README.md"), File.join(seed, "README.md"))
    git(seed, "init", "--quiet")
    git(seed, "checkout", "-b", "main")
    git(seed, "add", "Formula/pm.rb", "README.md")
    git(seed, "-c", "commit.gpgsign=false", "-c", "user.name=Maintainer", "-c", "user.email=maintainer@example.com", "commit", "--quiet", "-m", "initial")
    git(seed, "init", "--bare", "--quiet", remote)
    git(seed, "remote", "add", "origin", remote)
    git(seed, "push", "--quiet", "origin", "main")
    git(seed, "--git-dir", remote, "symbolic-ref", "HEAD", "refs/heads/main")
    system("git", "clone", "--quiet", remote, work) || raise("git clone failed")
    git(work, "switch", "main")

    yield work, remote
  end

  def create_formula_branch(work, branch, metadata, bot:)
    metadata_path = metadata_file(metadata)
    git(work, "fetch", "--quiet", "origin", "main")
    git(work, "switch", "-C", branch, "origin/main")
    PMFormulaBump::Operations.new(root: work).apply(
      metadata_path: metadata_path,
      formula_path: "Formula/pm.rb",
      readme_path: "README.md",
      write: true,
    )
    git(work, "add", "--", *PMFormulaPR::ALLOWED_CHANGED_PATHS)
    env = bot ? bot_commit_env(metadata) : human_commit_env(metadata)
    git(
      work,
      "-c", "commit.gpgsign=false",
      "commit", "--quiet", "--message", PMFormulaPR.commit_subject(metadata),
      env: env,
    )
    sha = git(work, "rev-parse", "HEAD").strip
    git(work, "push", "--quiet", "--force", "origin", "HEAD:refs/heads/#{branch}")
    sha
  end

  def advance_remote_main(work)
    git(work, "switch", "main")
    FileUtils.mkdir_p(File.join(work, "docs"))
    File.write(File.join(work, "docs/notes.md"), "main advanced without changing formula metadata\n")
    git(work, "add", "docs/notes.md")
    git(
      work,
      "-c", "commit.gpgsign=false",
      "-c", "user.name=Maintainer",
      "-c", "user.email=maintainer@example.com",
      "commit", "--quiet", "--message", "advance main",
    )
    git(work, "push", "--quiet", "origin", "HEAD:refs/heads/main")
  end

  def bot_commit_env(metadata)
    date = metadata.fetch("build_date")
    {
      "GIT_AUTHOR_NAME" => PMFormulaPR::BOT_NAME,
      "GIT_AUTHOR_EMAIL" => PMFormulaPR::BOT_EMAIL,
      "GIT_AUTHOR_DATE" => date,
      "GIT_COMMITTER_NAME" => PMFormulaPR::BOT_NAME,
      "GIT_COMMITTER_EMAIL" => PMFormulaPR::BOT_EMAIL,
      "GIT_COMMITTER_DATE" => date,
    }
  end

  def human_commit_env(metadata)
    bot_commit_env(metadata).merge(
      "GIT_AUTHOR_NAME" => "Human Maintainer",
      "GIT_AUTHOR_EMAIL" => "human@example.com",
      "GIT_COMMITTER_NAME" => "Human Maintainer",
      "GIT_COMMITTER_EMAIL" => "human@example.com",
    )
  end

  def metadata_file(metadata)
    dir = Dir.mktmpdir("pm-formula-pr-metadata-")
    @tmpdirs << dir
    path = File.join(dir, "metadata.json")
    File.write(path, PMFormulaBump.stable_json(metadata))
    path
  end

  def verification_file(metadata, verification_overrides: {})
    dir = Dir.mktmpdir("pm-formula-pr-verification-")
    @tmpdirs << dir
    path = File.join(dir, "verification.json")
    File.write(path, "#{JSON.pretty_generate(verification_hash(metadata).merge(verification_overrides))}\n")
    path
  end

  def verification_hash(metadata)
    version = metadata.fetch("version")
    {
      "schema" => PMReleaseVerifier::VERIFICATION_SCHEMA,
      "dispatch_schema" => PMReleaseVerifier::FORMULA_DISPATCH_SCHEMA,
      "source_repo" => PMFormulaBump::SOURCE_REPO,
      "version" => version,
      "tag" => metadata.fetch("tag"),
      "release_id" => "9001",
      "target_commitish_policy" => "ignore",
      "source_run_id" => "9002",
      "formula_dry_run" => "dry-run: would update Formula/pm.rb and README.md",
      "formula_action" => "update",
      "metadata" => metadata,
      "release_assets" => {
        "asset_count" => PMReleaseVerifier.expected_release_asset_names(version).length,
        "signed_subject_count" => PMReleaseVerifier.signed_subject_names(version).length,
        "expected_assets" => PMReleaseVerifier.expected_release_asset_names(version),
        "checksummed_assets" => PMReleaseVerifier.expected_subject_asset_names(version),
      },
    }
  end

  def remote_head(work, branch)
    output = git(work, "ls-remote", "--heads", "origin", branch)
    return nil if output.empty?

    output.split(/\s+/).first
  end

  def remote_branch_names(work)
    git(work, "ls-remote", "--heads", "origin").lines.map { |line| line.split(%r{/heads/}, 2).fetch(1).strip }
  end

  def git(repo, *args, env: {})
    stdout, stderr, status = Open3.capture3(env, "git", "-C", repo, *args)
    assert status.success?, stderr
    stdout
  end
end
