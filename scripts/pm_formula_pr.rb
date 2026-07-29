#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "json"
require "open3"
require "optparse"
require "tempfile"

require_relative "pm_formula_bump"
require_relative "pm_release_verifier"

module PMFormulaPR
  class Error < PMFormulaBump::Error; end

  TARGET_REPOSITORY = "polymetrics-ai/homebrew-tap"
  BASE_BRANCH = "main"
  BRANCH_PREFIX = "pm-release"
  TOKEN_ENV_VAR = "PM_BRANCH_PUSH_TOKEN"
  BOT_LOGIN = "pm-homebrew-pr-bot[bot]"
  BOT_APP_ID = "4421666"
  BOT_NAME = BOT_LOGIN
  BOT_EMAIL = "#{BOT_APP_ID}+#{BOT_LOGIN}@users.noreply.github.com"
  COMMIT_SUBJECT_PREFIX = "Bump PM to"
  ALLOWED_CHANGED_PATHS = %w[Formula/pm.rb README.md].freeze
  BRANCH_PATTERN = /\Apm-release\/v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z/

  module_function

  def branch_for(metadata)
    tag = PMFormulaBump.validate_stable_tag!(metadata.fetch("tag"))
    branch = "#{BRANCH_PREFIX}/#{tag}"
    fail Error, "automation branch must not target #{BASE_BRANCH}" if branch == BASE_BRANCH
    fail Error, "automation branch #{branch.inspect} is not a deterministic PM release branch" unless BRANCH_PATTERN.match?(branch)

    branch
  end

  def required_app_token(env: ENV)
    token = env.fetch(TOKEN_ENV_VAR, nil)
    fail Error, "#{TOKEN_ENV_VAR} is required for branch and PR mutations" if token.nil? || token.empty?

    token
  end

  def commit_subject(metadata)
    "#{COMMIT_SUBJECT_PREFIX} #{metadata.fetch("tag")}"
  end

  class Git
    def initialize(root:, push_token: PMFormulaPR.required_app_token)
      fail Error, "#{TOKEN_ENV_VAR} is required for branch and PR mutations" if push_token.nil? || push_token.empty?

      @root = File.realpath(root)
      @push_token = push_token
      @basic_auth = Base64.strict_encode64("x-access-token:#{push_token}")
    end

    attr_reader :root

    def run(*args, env: {})
      stdout, stderr, status = Open3.capture3(env, "git", "-C", root, *args)
      return stdout if status.success?

      fail Error, "git #{args.join(" ")} failed#{error_suffix(stdout, stderr)}"
    end

    def success?(*args)
      _stdout, _stderr, status = Open3.capture3("git", "-C", root, *args)
      status.success?
    end

    def clean_tracked_worktree?
      run("status", "--porcelain=v1", "--untracked-files=no").empty?
    end

    def fetch_branch(remote, branch)
      run("fetch", "--prune", remote, "+refs/heads/#{branch}:refs/remotes/#{remote}/#{branch}")
    end

    def ls_remote_head(remote, branch)
      output = run("ls-remote", "--heads", remote, branch)
      return nil if output.empty?

      lines = output.lines.map(&:strip).reject(&:empty?)
      fail Error, "remote branch lookup for #{branch} returned multiple refs" unless lines.length == 1

      sha, ref = lines.first.split(/\s+/, 2)
      expected_ref = "refs/heads/#{branch}"
      unless PMFormulaBump::COMMIT_PATTERN.match?(sha) && ref == expected_ref
        fail Error, "remote branch lookup for #{branch} returned unexpected ref metadata"
      end
      sha
    end

    def push(remote, branch, expected_old_sha: nil)
      args = ["push"]
      args << "--force-with-lease=refs/heads/#{branch}:#{expected_old_sha}" if expected_old_sha
      args += [remote, "HEAD:refs/heads/#{branch}"]
      run(*args, env: push_env)
    end

    def push_env
      {
        "GIT_TERMINAL_PROMPT" => "0",
        "GIT_CONFIG_COUNT" => "2",
        "GIT_CONFIG_KEY_0" => "http.https://github.com/.extraheader",
        "GIT_CONFIG_VALUE_0" => "AUTHORIZATION: basic #{@basic_auth}",
        "GIT_CONFIG_KEY_1" => "credential.helper",
        "GIT_CONFIG_VALUE_1" => "",
      }
    end

    def error_suffix(stdout, stderr)
      detail = stderr.empty? ? stdout : stderr
      detail = detail.gsub(@push_token, "[REDACTED]") if @push_token && !@push_token.empty?
      detail = detail.gsub(@basic_auth, "[REDACTED]") if @basic_auth
      detail = detail.lines.first(5).join.strip
      detail.empty? ? "" : ": #{detail}"
    end
  end

  class PullRequestClient
    def initialize(repository: TARGET_REPOSITORY, token: PMFormulaPR.required_app_token)
      fail Error, "#{TOKEN_ENV_VAR} is required for branch and PR mutations" if token.nil? || token.empty?

      @repository = repository
      @token = token
    end

    def open_pr_for_branch(branch, base_branch)
      owner = @repository.split("/").fetch(0)
      prs = gh_json(
        "repos/#{@repository}/pulls",
        "--method", "GET",
        "--field", "state=open",
        "--field", "base=#{base_branch}",
        "--field", "head=#{owner}:#{branch}",
      )
      fail Error, "GitHub API returned non-array open PR response" unless prs.is_a?(Array)
      fail Error, "multiple open PRs already exist for #{branch}" if prs.length > 1

      prs.first
    end

    def create_pr(branch:, base_branch:, title:, body:)
      gh_json(
        "repos/#{@repository}/pulls",
        "--method", "POST",
        "--field", "base=#{base_branch}",
        "--field", "head=#{branch}",
        "--field", "title=#{title}",
        "--field", "body=#{body}",
        "--field", "maintainer_can_modify=true",
      )
    end

    def update_pr(number:, title:, body:)
      gh_json(
        "repos/#{@repository}/pulls/#{number}",
        "--method", "PATCH",
        "--field", "title=#{title}",
        "--field", "body=#{body}",
      )
    end

    private

    def gh_json(*args)
      stdout, stderr, status = Open3.capture3(gh_env, "gh", "api", *args)
      return JSON.parse(stdout) if status.success?

      detail = stderr.empty? ? stdout : stderr
      [@token, ENV["GH_TOKEN"], ENV["GITHUB_TOKEN"], ENV[TOKEN_ENV_VAR]].uniq.each do |token|
        detail = detail.gsub(token, "[REDACTED]") if token && !token.empty?
      end
      fail Error, "gh api #{args.first} failed: #{detail.lines.first(5).join.strip}"
    rescue JSON::ParserError
      raise Error, "gh api #{args.first} returned invalid JSON"
    end

    def gh_env
      {
        "GH_TOKEN" => @token,
        "GITHUB_TOKEN" => nil,
        "GH_PROMPT_DISABLED" => "1",
      }
    end
  end

  class Operations
    def initialize(root: PMFormulaBump.default_root, git: nil, pull_requests: nil)
      @root = File.realpath(root)
      @paths = PMFormulaBump::Paths.new(root: @root)
      @git = git || Git.new(root: @root)
      @pull_requests = pull_requests || PullRequestClient.new
      @formula_operations = PMFormulaBump::Operations.new(root: @root)
    end

    def prepare(metadata_path:, verification_path:, repository: TARGET_REPOSITORY, remote: "origin", base_branch: BASE_BRANCH)
      fail Error, "repository must be #{TARGET_REPOSITORY}" unless repository == TARGET_REPOSITORY
      fail Error, "base branch must be #{BASE_BRANCH}" unless base_branch == BASE_BRANCH
      fail Error, "worktree has unexpected tracked changes" unless @git.clean_tracked_worktree?

      metadata = load_metadata(metadata_path)
      verification = load_verification(verification_path, metadata)
      branch = PMFormulaPR.branch_for(metadata)
      @git.fetch_branch(remote, base_branch)
      base_sha = @git.run("rev-parse", "refs/remotes/#{remote}/#{base_branch}").strip
      @git.run("switch", "--detach", base_sha)

      formula_state = @formula_operations.status(
        metadata_path: metadata_path,
        formula_path: "Formula/pm.rb",
        readme_path: "README.md",
      )
      case formula_state.fetch("action")
      when PMFormulaBump::FormulaState::ACTION_ALREADY_CURRENT, PMFormulaBump::FormulaState::ACTION_NEWER_FORMULA
        return no_mutation_result(branch, formula_state)
      when PMFormulaBump::FormulaState::ACTION_METADATA_CONFLICT
        fail Error, formula_state.fetch("message")
      end

      existing_sha = @git.ls_remote_head(remote, branch)
      @git.fetch_branch(remote, branch) if existing_sha

      deterministic_sha = build_deterministic_commit(metadata_path, metadata, branch, base_sha)
      branch_state = converge_branch(remote, branch, base_sha, existing_sha, deterministic_sha, metadata)
      pr = create_or_update_pr(branch, base_branch, metadata, verification)

      {
        "state" => branch_state,
        "branch" => branch,
        "commit" => deterministic_sha,
        "pr_action" => pr.fetch("action"),
        "pr_number" => pr.fetch("number"),
        "pr_url" => pr.fetch("url"),
        "mutated" => branch_state != "branch-current" || pr.fetch("action") != "updated",
      }
    end

    private

    def load_metadata(path)
      resolved = @paths.metadata_path(path, "metadata")
      fail Error, "metadata file does not exist: #{resolved}" unless File.file?(resolved)

      PMFormulaBump.metadata_from_hash(JSON.parse(File.read(resolved)))
    rescue JSON::ParserError
      raise Error, "metadata file is not valid JSON"
    end

    def load_verification(path, metadata)
      resolved = @paths.metadata_path(path, "verification")
      fail Error, "verification file does not exist: #{resolved}" unless File.file?(resolved)

      verification = JSON.parse(File.read(resolved))
      fail Error, "verification must be a JSON object" unless verification.is_a?(Hash)
      fail Error, "verification schema is unsupported" unless verification["schema"] == PMReleaseVerifier::VERIFICATION_SCHEMA
      unless verification["dispatch_schema"] == PMReleaseVerifier::FORMULA_DISPATCH_SCHEMA
        fail Error, "verification dispatch_schema must be #{PMReleaseVerifier::FORMULA_DISPATCH_SCHEMA}"
      end
      fail Error, "verification metadata does not match formula metadata" unless verification["metadata"] == metadata
      unless verification["source_repo"] == PMFormulaBump::SOURCE_REPO && verification["tag"] == metadata.fetch("tag")
        fail Error, "verification source does not match formula metadata"
      end

      release_assets = verification["release_assets"]
      fail Error, "verification release_assets must be a JSON object" unless release_assets.is_a?(Hash)
      expected_assets = PMReleaseVerifier.expected_release_asset_names(metadata.fetch("version"))
      expected_subjects = PMReleaseVerifier.signed_subject_names(metadata.fetch("version"))
      unless release_assets["asset_count"] == expected_assets.length && release_assets["expected_assets"] == expected_assets
        fail Error, "verification asset summary does not match expected PM release assets"
      end
      unless release_assets["signed_subject_count"] == expected_subjects.length
        fail Error, "verification signed subject summary does not match expected PM release assets"
      end

      verification
    rescue JSON::ParserError
      raise Error, "verification file is not valid JSON"
    end

    def no_mutation_result(branch, formula_state)
      {
        "state" => formula_state.fetch("action"),
        "branch" => branch,
        "message" => formula_state.fetch("message"),
        "mutated" => false,
      }
    end

    def build_deterministic_commit(metadata_path, metadata, branch, base_sha)
      @git.run("switch", "--detach", base_sha)
      @git.run("switch", "-C", branch, base_sha)
      @formula_operations.apply(
        metadata_path: metadata_path,
        formula_path: "Formula/pm.rb",
        readme_path: "README.md",
        write: true,
      )
      assert_changed_files_exact!("git diff", @git.run("diff", "--name-only").lines.map(&:chomp))
      @git.run("add", "--", *ALLOWED_CHANGED_PATHS)
      @git.run(
        "-c", "commit.gpgsign=false",
        "commit",
        "--message", PMFormulaPR.commit_subject(metadata),
        env: deterministic_commit_env(metadata),
      )
      sha = @git.run("rev-parse", "HEAD").strip
      assert_changed_files_exact!("branch diff", @git.run("diff", "--name-only", "#{base_sha}..HEAD").lines.map(&:chomp))
      sha
    end

    def deterministic_commit_env(metadata)
      date = metadata.fetch("build_date")
      {
        "GIT_AUTHOR_NAME" => BOT_NAME,
        "GIT_AUTHOR_EMAIL" => BOT_EMAIL,
        "GIT_AUTHOR_DATE" => date,
        "GIT_COMMITTER_NAME" => BOT_NAME,
        "GIT_COMMITTER_EMAIL" => BOT_EMAIL,
        "GIT_COMMITTER_DATE" => date,
      }
    end

    def assert_changed_files_exact!(description, files)
      actual = files.reject(&:empty?).sort
      expected = ALLOWED_CHANGED_PATHS.sort
      return if actual == expected

      fail Error, "#{description} changed files must be exactly #{expected.join(", ")}; got #{actual.join(", ")}"
    end

    def converge_branch(remote, branch, base_sha, existing_sha, deterministic_sha, metadata)
      if existing_sha.nil?
        @git.push(remote, branch)
        return "branch-absent"
      end
      return "branch-current" if existing_sha == deterministic_sha

      unless bot_owned_stale_branch?(remote, branch, base_sha, metadata)
        fail Error, "refusing to overwrite existing #{branch}; branch is not a bot-owned deterministic formula branch"
      end

      @git.push(remote, branch, expected_old_sha: existing_sha)
      "branch-stale-bot"
    end

    def bot_owned_stale_branch?(remote, branch, base_sha, metadata)
      remote_ref = "refs/remotes/#{remote}/#{branch}"
      merge_base = @git.run("merge-base", base_sha, remote_ref).strip
      return false if merge_base.empty?

      commits = @git.run("rev-list", "--reverse", remote_ref, "--not", base_sha).lines.map(&:chomp).reject(&:empty?)
      return false if commits.empty?

      commits.all? { |sha| bot_owned_deterministic_commit?(sha, metadata) } &&
        stale_branch_changed_files_allowed?(merge_base, remote_ref) &&
        branch_content_matches_metadata?(remote_ref, metadata)
    rescue Error
      false
    end

    def bot_owned_deterministic_commit?(sha, metadata)
      fields = @git.run("show", "--no-patch", "--format=%an%x00%ae%x00%cn%x00%ce%x00%s", sha).split("\0", 5)
      return false unless fields.length == 5

      author_name, author_email, committer_name, committer_email, subject = fields
      [author_name, committer_name].all? { |value| value == BOT_NAME } &&
        [author_email, committer_email].all? { |value| value == BOT_EMAIL } &&
        subject.strip == PMFormulaPR.commit_subject(metadata)
    end

    def stale_branch_changed_files_allowed?(merge_base, remote_ref)
      files = @git.run("diff", "--name-only", "#{merge_base}..#{remote_ref}").lines.map(&:chomp)
      files.sort == ALLOWED_CHANGED_PATHS.sort
    end

    def branch_content_matches_metadata?(remote_ref, metadata)
      formula_text = @git.run("show", "#{remote_ref}:Formula/pm.rb")
      readme_text = @git.run("show", "#{remote_ref}:README.md")
      state = PMFormulaBump::FormulaState.classify(formula_text, readme_text, metadata)
      state.fetch("action") == PMFormulaBump::FormulaState::ACTION_ALREADY_CURRENT
    end

    def create_or_update_pr(branch, base_branch, metadata, verification)
      title = PMFormulaPR.commit_subject(metadata)
      body = pr_body(metadata, verification)
      existing = @pull_requests.open_pr_for_branch(branch, base_branch)
      if existing
        assert_bot_authored_pr!(existing, branch)
        updated = @pull_requests.update_pr(number: existing.fetch("number"), title: title, body: body)
        return pr_result("updated", updated)
      end

      created = @pull_requests.create_pr(branch: branch, base_branch: base_branch, title: title, body: body)
      pr_result("created", created)
    end

    def assert_bot_authored_pr!(pr, branch)
      return if pr.dig("user", "login") == BOT_LOGIN && pr.dig("user", "type") == "Bot"

      fail Error, "refusing to update existing PR for #{branch}; PR author is not #{BOT_LOGIN}"
    end

    def pr_result(action, pr)
      {
        "action" => action,
        "number" => pr.fetch("number"),
        "url" => pr.fetch("html_url"),
      }
    end

    def pr_body(metadata, verification)
      <<~MARKDOWN
        ## PM Homebrew formula update

        This PR was prepared by `#{BOT_LOGIN}` after the tap-owned PM formula update workflow independently verified the immutable upstream release evidence.

        - tag: `#{metadata.fetch("tag")}`
        - version: `#{metadata.fetch("version")}`
        - source: `#{metadata.fetch("source_url")}`
        - source SHA-256: `#{metadata.fetch("source_sha256")}`
        - commit: `#{metadata.fetch("commit")}`
        - build date: `#{metadata.fetch("build_date")}`
        - release id: `#{verification.fetch("release_id")}`
        - verified release assets: `#{verification.fetch("release_assets").fetch("asset_count")}`
        - changed files: `#{ALLOWED_CHANGED_PATHS.join("`, `")}`

        Maintainers must wait for the push-triggered Homebrew validation matrix and PR author authorization before merging. The automation App cannot update `main` or bypass branch protection.
      MARKDOWN
    end
  end

  class CLI
    def initialize(argv, operations: Operations.new)
      @argv = argv.dup
      @operations = operations
    end

    def run
      command = @argv.shift
      fail Error, "command must be prepare" unless command == "prepare"

      options = parse_prepare_options
      result = @operations.prepare(**options)
      $stdout.write("#{JSON.pretty_generate(result)}\n")
      0
    rescue Error, PMFormulaBump::Error, OptionParser::ParseError, KeyError => e
      $stderr.puts("pm_formula_pr: #{e.message}")
      1
    end

    private

    def parse_prepare_options
      options = {
        repository: TARGET_REPOSITORY,
        remote: "origin",
        base_branch: BASE_BRANCH,
      }
      parser = OptionParser.new do |opts|
        opts.banner = "Usage: #{$PROGRAM_NAME} prepare --metadata <path> --verification <path> [--repository #{TARGET_REPOSITORY}] [--remote origin] [--base main]"
        opts.on("--metadata PATH") { |value| options[:metadata_path] = value }
        opts.on("--verification PATH") { |value| options[:verification_path] = value }
        opts.on("--repository REPO") { |value| options[:repository] = value }
        opts.on("--remote REMOTE") { |value| options[:remote] = value }
        opts.on("--base BRANCH") { |value| options[:base_branch] = value }
      end
      parser.parse!(@argv)
      fail Error, "unexpected positional arguments: #{@argv.join(" ")}" unless @argv.empty?
      %i[metadata_path verification_path].each { |key| fail Error, "--#{key.to_s.tr("_", "-")} is required" unless options[key] }

      options
    end
  end
end

if $PROGRAM_NAME == __FILE__
  exit PMFormulaPR::CLI.new(ARGV).run
end
