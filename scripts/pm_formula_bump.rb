#!/usr/bin/env ruby
# frozen_string_literal: true

require "digest"
require "English"
require "fileutils"
require "json"
require "net/http"
require "optparse"
require "rubygems/package"
require "set"
require "tempfile"
require "time"
require "uri"
require "zlib"

module PMFormulaBump
  class Error < StandardError; end

  SOURCE_REPO = "polymetrics-ai/cli"
  SOURCE_ARCHIVE_BASE = "https://github.com/#{SOURCE_REPO}/archive/refs/tags"
  METADATA_SCHEMA = "pm-homebrew-formula-metadata/v1"
  STABLE_TAG_PATTERN = /\Av(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z/
  SHA256_PATTERN = /\A[0-9a-f]{64}\z/
  COMMIT_PATTERN = /\A[0-9a-f]{40}\z/
  UTC_TIME_PATTERN = /\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\z/
  REQUIRED_ARCHIVE_FILES = %w[
    go.mod
    cmd/pm
    LICENSE
    NOTICE
    LICENSING.md
    internal/connectors/defs/LICENSE
  ].freeze
  ALLOWED_TRACKED_PATHS = %w[Formula/pm.rb README.md].freeze
  METADATA_KEYS = %w[
    schema
    source_repo
    tag
    version
    source_url
    source_sha256
    commit
    build_date
  ].freeze

  module_function

  def default_root
    File.expand_path("..", __dir__)
  end

  def validate_stable_tag!(tag)
    fail Error, "tag is required" if tag.nil? || tag.empty?
    fail Error, "tag must not look like an option" if tag.start_with?("-")

    match = STABLE_TAG_PATTERN.match(tag)
    fail Error, "tag must be stable semver like v1.2.3" unless match

    tag
  end

  def version_from_tag(tag)
    validate_stable_tag!(tag).delete_prefix("v")
  end

  def source_url_for(tag)
    "#{SOURCE_ARCHIVE_BASE}/#{validate_stable_tag!(tag)}.tar.gz"
  end

  def normalize_build_date(value)
    fail Error, "build_date is required" if value.nil? || value.empty?

    Time.iso8601(value).utc.iso8601
  rescue ArgumentError
    raise Error, "build_date must be an ISO-8601 timestamp"
  end

  def compare_versions(left, right)
    left_parts = parse_version(left)
    right_parts = parse_version(right)

    left_parts <=> right_parts
  end

  def parse_version(version)
    match = /\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\z/.match(version.to_s)
    fail Error, "version must be stable semver without leading v" unless match

    match.captures.map(&:to_i)
  end

  def stable_json(hash)
    ordered = {}
    METADATA_KEYS.each { |key| ordered[key] = hash.fetch(key) }
    "#{JSON.pretty_generate(ordered)}\n"
  end

  def metadata_from_hash(hash)
    fail Error, "metadata must be a JSON object" unless hash.is_a?(Hash)

    unknown = hash.keys - METADATA_KEYS
    missing = METADATA_KEYS - hash.keys
    fail Error, "metadata contains unexpected keys: #{unknown.sort.join(", ")}" unless unknown.empty?
    fail Error, "metadata is missing keys: #{missing.sort.join(", ")}" unless missing.empty?

    tag = validate_stable_tag!(string_field(hash, "tag"))
    version = string_field(hash, "version")
    fail Error, "metadata version does not match tag" unless version == version_from_tag(tag)
    fail Error, "metadata schema is unsupported" unless string_field(hash, "schema") == METADATA_SCHEMA
    fail Error, "metadata source_repo must be #{SOURCE_REPO}" unless string_field(hash, "source_repo") == SOURCE_REPO
    fail Error, "metadata source_url must be the constant source archive URL" unless string_field(hash, "source_url") == source_url_for(tag)

    source_sha256 = string_field(hash, "source_sha256")
    fail Error, "metadata source_sha256 must be 64 lowercase hex characters" unless SHA256_PATTERN.match?(source_sha256)

    commit = string_field(hash, "commit")
    fail Error, "metadata commit must be 40 lowercase hex characters" unless COMMIT_PATTERN.match?(commit)

    raw_build_date = string_field(hash, "build_date")
    build_date = normalize_build_date(raw_build_date)
    unless raw_build_date == build_date && UTC_TIME_PATTERN.match?(build_date)
      fail Error, "metadata build_date must be normalized UTC with Z suffix"
    end

    {
      "schema" => METADATA_SCHEMA,
      "source_repo" => SOURCE_REPO,
      "tag" => tag,
      "version" => version,
      "source_url" => source_url_for(tag),
      "source_sha256" => source_sha256,
      "commit" => commit,
      "build_date" => build_date,
    }
  end

  def string_field(hash, key)
    value = hash[key]
    fail Error, "metadata #{key} must be a string" unless value.is_a?(String)
    fail Error, "metadata #{key} must not be empty" if value.empty?
    fail Error, "metadata #{key} must not look like an option" if value.start_with?("-")

    value
  end

  def build_metadata(tag:, source_sha256:, commit:, build_date:)
    metadata_from_hash(
      "schema" => METADATA_SCHEMA,
      "source_repo" => SOURCE_REPO,
      "tag" => validate_stable_tag!(tag),
      "version" => version_from_tag(tag),
      "source_url" => source_url_for(tag),
      "source_sha256" => source_sha256,
      "commit" => commit,
      "build_date" => normalize_build_date(build_date),
    )
  end

  class Paths
    def initialize(root: PMFormulaBump.default_root)
      @root = File.realpath(root)
    end

    attr_reader :root

    def allowed_path(path, expected_relative)
      fail Error, "#{expected_relative} path is required" if path.nil? || path.empty?
      fail Error, "#{expected_relative} path must not look like an option" if path.start_with?("-")

      resolved = File.expand_path(path, root)
      expected = File.join(root, expected_relative)
      fail Error, "#{path} must resolve to #{expected_relative}" unless resolved == expected

      resolved
    end

    def metadata_path(path, description)
      fail Error, "#{description} is required" if path.nil? || path.empty?
      fail Error, "#{description} must not look like an option" if path.start_with?("-")

      expanded = real_or_expanded_path(path)
      if inside_repo?(expanded)
        fail Error, "#{description} must be outside the repository so metadata is not written to tracked paths"
      end

      expanded
    end

    def ensure_metadata_parent!(path)
      parent = File.dirname(path)
      fail Error, "metadata parent directory does not exist: #{parent}" unless Dir.exist?(parent)
    end

    def inside_repo?(path)
      expanded = File.expand_path(path)
      expanded == root || expanded.start_with?("#{root}/")
    end

    def real_or_expanded_path(path)
      expanded = File.expand_path(path, Dir.pwd)
      return File.realpath(expanded) if File.exist?(expanded)

      parent = File.dirname(expanded)
      return File.join(File.realpath(parent), File.basename(expanded)) if Dir.exist?(parent)

      expanded
    end
  end

  class GitStatus
    def initialize(root: PMFormulaBump.default_root)
      @root = File.realpath(root)
    end

    def assert_no_unexpected_tracked_changes!
      status = run_git("status", "--porcelain=v1", "--untracked-files=no")
      unexpected = status.lines.flat_map { |line| tracked_paths_from_status(line) }
                         .reject { |path| ALLOWED_TRACKED_PATHS.include?(path) }
                         .uniq
                         .sort
      return if unexpected.empty?

      fail Error, "unexpected tracked-file changes present: #{unexpected.join(", ")}"
    end

    private

    def run_git(*args)
      output = IO.popen(["git", "-C", @root, *args], err: %i[child out], &:read)
      fail Error, "git #{args.join(" ")} failed" unless $CHILD_STATUS&.success?

      output
    rescue SystemCallError => e
      raise Error, "git is required to inspect tracked-file changes: #{e.message}"
    end

    def tracked_paths_from_status(line)
      path_part = line[3..]&.strip.to_s
      return [] if path_part.empty?

      path_part.split(" -> ")
    end
  end

  class GitHubClient
    API_HOST = "api.github.com"
    REDIRECT_HOSTS = %w[github.com codeload.github.com].freeze

    def release_by_tag(tag)
      api_json("/repos/#{SOURCE_REPO}/releases/tags/#{tag}")
    end

    def tag_ref(tag)
      api_json("/repos/#{SOURCE_REPO}/git/ref/tags/#{tag}")
    end

    def tag_object(sha)
      api_json("/repos/#{SOURCE_REPO}/git/tags/#{sha}")
    end

    def commit(commitish)
      api_json("/repos/#{SOURCE_REPO}/commits/#{commitish}")
    end

    def download_archive_sha256(source_url, tag)
      fail Error, "source archive URL is not constant for #{tag}" unless source_url == PMFormulaBump.source_url_for(tag)

      Tempfile.create(["pm-source-", ".tar.gz"]) do |file|
        file.binmode
        download_to_file(URI(source_url), file)
        file.flush
        file.rewind
        verify_archive!(file.path)
        Digest::SHA256.file(file.path).hexdigest
      end
    end

    private

    def api_json(path)
      uri = URI::HTTPS.build(host: API_HOST, path: path)
      response = request(uri)
      unless response.is_a?(Net::HTTPSuccess)
        fail Error, "GitHub API request failed for #{path}: HTTP #{response.code}"
      end

      JSON.parse(response.body)
    rescue JSON::ParserError
      raise Error, "GitHub API returned invalid JSON for #{path}"
    end

    def request(uri)
      Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
        http.request(build_request(uri))
      end
    end

    def download_to_file(uri, file, redirects_remaining = 5)
      fail Error, "too many source archive redirects" if redirects_remaining.negative?
      fail Error, "source archive URL must use https" unless uri.scheme == "https"
      fail Error, "unexpected source archive host: #{uri.host}" unless REDIRECT_HOSTS.include?(uri.host)

      response = download_response(uri, file)
      case response
      when Net::HTTPRedirection
        location = response["location"]
        fail Error, "source archive redirect missing location" if location.nil? || location.empty?

        download_to_file(URI.join(uri, location), file, redirects_remaining - 1)
      when Net::HTTPSuccess
        nil
      else
        fail Error, "source archive download failed: HTTP #{response.code}"
      end
    end

    def download_response(uri, file)
      response = nil
      Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
        http.request(build_request(uri)) do |http_response|
          response = http_response
          http_response.read_body { |chunk| file.write(chunk) } if http_response.is_a?(Net::HTTPSuccess)
        end
      end
      response
    end

    def build_request(uri)
      request = Net::HTTP::Get.new(uri)
      request["Accept"] = "application/vnd.github+json"
      request["X-GitHub-Api-Version"] = "2022-11-28"
      request["User-Agent"] = "polymetrics-homebrew-tap-formula-bump"
      token = ENV["GITHUB_TOKEN"]
      request["Authorization"] = "Bearer #{token}" if token && !token.empty?
      request
    end

    def verify_archive!(path)
      entries = []
      Zlib::GzipReader.open(path) do |gzip|
        Gem::Package::TarReader.new(gzip) do |tar|
          tar.each do |entry|
            name = entry.full_name
            next if name == "pax_global_header" || name.match?(/\A[0-9a-f]{40}\.(?:paxheader|data)\z/)

            fail Error, "source archive contains an absolute path" if name.start_with?("/")
            fail Error, "source archive contains path traversal" if name.split("/").include?("..")

            entries << name
          end
        end
      end

      prefix = entries.map { |name| name.split("/").first }.uniq
      fail Error, "source archive must contain exactly one top-level directory" unless prefix.length == 1

      normalized = entries.map { |name| name.delete_prefix("#{prefix.first}/") }.to_set
      missing = REQUIRED_ARCHIVE_FILES.reject do |required|
        normalized.include?(required) || normalized.any? { |name| name.start_with?("#{required}/") }
      end
      fail Error, "source archive is missing required files: #{missing.join(", ")}" unless missing.empty?
    rescue Zlib::GzipFile::Error, Gem::Package::TarInvalidError => e
      raise Error, "source archive is not a valid tar.gz archive: #{e.message}"
    end
  end

  class Planner
    def initialize(client: GitHubClient.new)
      @client = client
    end

    def plan(tag)
      tag = PMFormulaBump.validate_stable_tag!(tag)
      release = @client.release_by_tag(tag)
      validate_release!(release, tag)

      tag_commit = resolve_tag_commit(tag)
      commit_json = @client.commit(tag_commit)
      build_date = commit_json.dig("commit", "committer", "date")
      fail Error, "commit response is missing committer date" unless build_date

      source_url = PMFormulaBump.source_url_for(tag)
      source_sha256 = @client.download_archive_sha256(source_url, tag)

      PMFormulaBump.build_metadata(
        tag: tag,
        source_sha256: source_sha256,
        commit: tag_commit,
        build_date: build_date,
      )
    end

    private

    def validate_release!(release, tag)
      fail Error, "release response must be a JSON object" unless release.is_a?(Hash)
      fail Error, "release tag_name does not match requested tag" unless release["tag_name"] == tag
      fail Error, "draft releases are not eligible for formula bumps" if release["draft"]
      fail Error, "prerelease versions are not eligible for formula bumps" if release["prerelease"]
      fail Error, "release must have published_at" if release["published_at"].to_s.empty?
    end

    def resolve_tag_commit(tag)
      ref = @client.tag_ref(tag)
      object = ref.fetch("object")
      type = object.fetch("type")
      sha = object.fetch("sha")

      case type
      when "commit"
        validate_commit_sha!(sha, "tag commit")
      when "tag"
        tag_object = @client.tag_object(validate_commit_sha!(sha, "annotated tag object"))
        fail Error, "annotated tag object must point to a commit" unless tag_object.dig("object", "type") == "commit"

        validate_commit_sha!(tag_object.dig("object", "sha"), "annotated tag commit")
      else
        fail Error, "tag ref must point to a commit or annotated tag, not #{type.inspect}"
      end
    end

    def validate_commit_sha!(sha, description)
      fail Error, "#{description} must be 40 lowercase hex characters" unless sha.is_a?(String) && COMMIT_PATTERN.match?(sha)

      sha
    end
  end

  class FormulaEditor
    FORMULA_PATTERNS = {
      source_url: /^  url "([^"]+)"$/,
      source_sha256: /^  sha256 "([0-9a-f]{64})"$/,
      version: %r{^      -X polymetrics\.ai/internal/cli\.version=([^\s]+)$},
      commit: %r{^      -X polymetrics\.ai/internal/cli\.commit=([0-9a-f]{40})$},
      build_date: %r{^      -X polymetrics\.ai/internal/cli\.buildDate=([^\s]+)$},
      test_version: /^    assert_equal "([^"]+)", version_json\["version"\]$/,
      test_commit: /^    assert_equal "([0-9a-f]{40})", version_json\["commit"\]$/,
      test_date: /^    assert_equal "([^"]+)", version_json\["date"\]$/,
    }.freeze

    def self.metadata(text)
      values = {
        "source_url" => capture(text, FORMULA_PATTERNS.fetch(:source_url), "formula source URL"),
        "source_sha256" => capture(text, FORMULA_PATTERNS.fetch(:source_sha256), "formula SHA-256"),
        "version" => capture(text, FORMULA_PATTERNS.fetch(:version), "formula linker version"),
        "commit" => capture(text, FORMULA_PATTERNS.fetch(:commit), "formula linker commit"),
        "build_date" => capture(text, FORMULA_PATTERNS.fetch(:build_date), "formula linker build date"),
      }

      test_version = capture(text, FORMULA_PATTERNS.fetch(:test_version), "formula test version expectation")
      test_commit = capture(text, FORMULA_PATTERNS.fetch(:test_commit), "formula test commit expectation")
      test_date = capture_optional(text, FORMULA_PATTERNS.fetch(:test_date))

      fail Error, "formula test version does not match linker version" unless test_version == values.fetch("version")
      fail Error, "formula test commit does not match linker commit" unless test_commit == values.fetch("commit")
      fail Error, "formula test date does not match linker build date" if test_date && test_date != values.fetch("build_date")

      values
    end

    def self.update(text, metadata)
      replacements = {
        FORMULA_PATTERNS.fetch(:source_url) => "  url \"#{metadata.fetch("source_url")}\"",
        FORMULA_PATTERNS.fetch(:source_sha256) => "  sha256 \"#{metadata.fetch("source_sha256")}\"",
        FORMULA_PATTERNS.fetch(:version) => "      -X polymetrics.ai/internal/cli.version=#{metadata.fetch("version")}",
        FORMULA_PATTERNS.fetch(:commit) => "      -X polymetrics.ai/internal/cli.commit=#{metadata.fetch("commit")}",
        FORMULA_PATTERNS.fetch(:build_date) => "      -X polymetrics.ai/internal/cli.buildDate=#{metadata.fetch("build_date")}",
        FORMULA_PATTERNS.fetch(:test_version) => "    assert_equal \"#{metadata.fetch("version")}\", version_json[\"version\"]",
        FORMULA_PATTERNS.fetch(:test_commit) => "    assert_equal \"#{metadata.fetch("commit")}\", version_json[\"commit\"]",
      }

      updated = replacements.reduce(text) do |current, (pattern, replacement)|
        replace_once(current, pattern, replacement)
      end

      date_line = "    assert_equal \"#{metadata.fetch("build_date")}\", version_json[\"date\"]"
      if FORMULA_PATTERNS.fetch(:test_date).match?(updated)
        replace_once(updated, FORMULA_PATTERNS.fetch(:test_date), date_line)
      else
        replace_once(updated, FORMULA_PATTERNS.fetch(:test_commit), "#{replacements.fetch(FORMULA_PATTERNS.fetch(:test_commit))}\n#{date_line}")
      end
    end

    def self.capture(text, pattern, description)
      matches = text.scan(pattern).flatten
      fail Error, "#{description} must appear exactly once" unless matches.length == 1

      matches.first
    end

    def self.capture_optional(text, pattern)
      matches = text.scan(pattern).flatten
      fail Error, "optional formula field appears more than once" if matches.length > 1

      matches.first
    end

    def self.replace_once(text, pattern, replacement)
      count = 0
      updated = text.gsub(pattern) do
        count += 1
        replacement
      end
      fail Error, "pattern #{pattern.inspect} must match exactly once" unless count == 1

      updated
    end
  end

  class ReadmeEditor
    TRUST_PATTERN = %r{
      -\ source:\ `([^`]+)`\n
      -\ SHA-256:\ `([0-9a-f]{64})`\n
      -\ build\ metadata\ embedded\ in\ `pm\ version\ --json`:\ version\ `([^`]+)`,\ commit\n
      \ \ `([0-9a-f]{40})`,\ and\ build\ date\n
      \ \ `([^`]+)`
    }x

    def self.metadata(text)
      match = TRUST_PATTERN.match(text)
      fail Error, "README trust metadata block must appear exactly once" unless match
      fail Error, "README trust metadata block must appear exactly once" if match.post_match.match?(TRUST_PATTERN)

      {
        "source_url" => match[1],
        "source_sha256" => match[2],
        "version" => match[3],
        "commit" => match[4],
        "build_date" => match[5],
      }
    end

    def self.update(text, metadata)
      replacement = <<~MARKDOWN.chomp
        - source: `#{metadata.fetch("source_url")}`
        - SHA-256: `#{metadata.fetch("source_sha256")}`
        - build metadata embedded in `pm version --json`: version `#{metadata.fetch("version")}`, commit
          `#{metadata.fetch("commit")}`, and build date
          `#{metadata.fetch("build_date")}`
      MARKDOWN

      count = 0
      updated = text.gsub(TRUST_PATTERN) do
        count += 1
        replacement
      end
      fail Error, "README trust metadata block must appear exactly once" unless count == 1

      updated
    end
  end

  class FormulaState
    ACTION_ALREADY_CURRENT = "already-current"
    ACTION_UPDATE = "update"
    ACTION_NEWER_FORMULA = "newer-formula"
    ACTION_METADATA_CONFLICT = "metadata-conflict"

    def self.classify(formula_text, readme_text, metadata)
      formula_metadata = FormulaEditor.metadata(formula_text)
      readme_metadata = ReadmeEditor.metadata(readme_text)
      drift = drift_keys(formula_metadata, readme_metadata)
      unless drift.empty?
        return result(
          ACTION_METADATA_CONFLICT,
          formula_metadata,
          metadata,
          "current Formula/pm.rb and README.md drift from release metadata: #{drift.join(", ")}",
        )
      end

      version_comparison = PMFormulaBump.compare_versions(
        formula_metadata.fetch("version"),
        metadata.fetch("version"),
      )
      case version_comparison
      when 1
        result(
          ACTION_NEWER_FORMULA,
          formula_metadata,
          metadata,
          "refusing to downgrade formula from #{formula_metadata.fetch("version")} to #{metadata.fetch("version")}",
        )
      when 0
        classify_same_version(formula_metadata, readme_metadata, metadata)
      else
        result(
          ACTION_UPDATE,
          formula_metadata,
          metadata,
          "Formula/pm.rb and README.md can be updated from #{formula_metadata.fetch("version")} to #{metadata.fetch("version")}",
        )
      end
    end

    def self.classify_same_version(formula_metadata, readme_metadata, metadata)
      expected = file_metadata(metadata)
      formula_drift = drift_keys(formula_metadata, expected)
      readme_drift = drift_keys(readme_metadata, expected)
      return result(ACTION_ALREADY_CURRENT, formula_metadata, metadata, "Formula/pm.rb and README.md already match metadata") if formula_drift.empty? && readme_drift.empty?

      messages = []
      messages << "same-version Formula/pm.rb drift from release metadata: #{formula_drift.join(", ")}" unless formula_drift.empty?
      messages << "same-version README.md drift from release metadata: #{readme_drift.join(", ")}" unless readme_drift.empty?
      result(ACTION_METADATA_CONFLICT, formula_metadata, metadata, messages.join("; "))
    end
    private_class_method :classify_same_version

    def self.drift_keys(actual, expected)
      expected.keys.each_with_object([]) do |key, result|
        result << key unless actual[key] == expected[key]
      end
    end
    private_class_method :drift_keys

    def self.file_metadata(metadata)
      {
        "source_url" => metadata.fetch("source_url"),
        "source_sha256" => metadata.fetch("source_sha256"),
        "version" => metadata.fetch("version"),
        "commit" => metadata.fetch("commit"),
        "build_date" => metadata.fetch("build_date"),
      }
    end
    private_class_method :file_metadata

    def self.result(action, current_metadata, target_metadata, message)
      {
        "action" => action,
        "current_version" => current_metadata.fetch("version"),
        "target_version" => target_metadata.fetch("version"),
        "tag" => target_metadata.fetch("tag"),
        "message" => message,
      }
    end
    private_class_method :result
  end

  class Operations
    def initialize(root: PMFormulaBump.default_root, planner: Planner.new)
      @root = File.realpath(root)
      @paths = Paths.new(root: @root)
      @git_status = GitStatus.new(root: @root)
      @planner = planner
    end

    def plan(tag:, metadata_out:)
      metadata_path = @paths.metadata_path(metadata_out, "metadata-out")
      @paths.ensure_metadata_parent!(metadata_path)
      metadata = @planner.plan(tag)
      json = PMFormulaBump.stable_json(metadata)
      atomic_write(metadata_path, json)
      json
    end

    def apply(metadata_path:, formula_path:, readme_path:, write:)
      metadata = load_metadata(metadata_path)
      formula = @paths.allowed_path(formula_path, "Formula/pm.rb")
      readme = @paths.allowed_path(readme_path, "README.md")
      @git_status.assert_no_unexpected_tracked_changes! if write

      formula_text = File.read(formula)
      readme_text = File.read(readme)
      assert_current_files_are_safe_to_update!(formula_text, readme_text, metadata)

      updated_formula = FormulaEditor.update(formula_text, metadata)
      updated_readme = ReadmeEditor.update(readme_text, metadata)

      if write && (formula_text != updated_formula || readme_text != updated_readme)
        File.write(formula, updated_formula)
        File.write(readme, updated_readme)
        @git_status.assert_no_unexpected_tracked_changes!
        "updated Formula/pm.rb and README.md\n"
      elsif write
        "Formula/pm.rb and README.md already match metadata\n"
      elsif formula_text == updated_formula && readme_text == updated_readme
        "dry-run: Formula/pm.rb and README.md already match metadata\n"
      else
        "dry-run: would update Formula/pm.rb and README.md\n"
      end
    end

    def check(metadata_path:, formula_path:, readme_path:)
      metadata = load_metadata(metadata_path)
      formula = @paths.allowed_path(formula_path, "Formula/pm.rb")
      readme = @paths.allowed_path(readme_path, "README.md")

      formula_text = File.read(formula)
      readme_text = File.read(readme)
      actual_formula = FormulaEditor.metadata(formula_text)
      actual_readme = ReadmeEditor.metadata(readme_text)
      expected = file_metadata(metadata)

      assert_metadata_equal!("Formula/pm.rb", actual_formula, expected)
      assert_metadata_equal!("README.md", actual_readme, expected)
      ensure_stable_format!("Formula/pm.rb", formula_text, FormulaEditor.update(formula_text, metadata))
      ensure_stable_format!("README.md", readme_text, ReadmeEditor.update(readme_text, metadata))

      "Formula/pm.rb and README.md match metadata\n"
    end

    def status(metadata_path:, formula_path:, readme_path:)
      metadata = load_metadata(metadata_path)
      formula = @paths.allowed_path(formula_path, "Formula/pm.rb")
      readme = @paths.allowed_path(readme_path, "README.md")

      FormulaState.classify(File.read(formula), File.read(readme), metadata)
    end

    private

    def load_metadata(path)
      metadata_path = @paths.metadata_path(path, "metadata")
      fail Error, "metadata file does not exist: #{metadata_path}" unless File.file?(metadata_path)

      PMFormulaBump.metadata_from_hash(JSON.parse(File.read(metadata_path)))
    rescue JSON::ParserError
      raise Error, "metadata file is not valid JSON"
    end

    def assert_current_files_are_safe_to_update!(formula_text, readme_text, metadata)
      state = FormulaState.classify(formula_text, readme_text, metadata)
      return if [FormulaState::ACTION_ALREADY_CURRENT, FormulaState::ACTION_UPDATE].include?(state.fetch("action"))

      fail Error, state.fetch("message")
    end

    def assert_metadata_equal!(description, actual, expected)
      drift = expected.keys.each_with_object([]) do |key, result|
        result << key unless actual[key] == expected[key]
      end
      return if drift.empty?

      fail Error, "#{description} drift from release metadata: #{drift.join(", ")}"
    end

    def ensure_stable_format!(description, current, generated)
      return if current == generated

      fail Error, "#{description} is not in stable generated format"
    end

    def file_metadata(metadata)
      {
        "source_url" => metadata.fetch("source_url"),
        "source_sha256" => metadata.fetch("source_sha256"),
        "version" => metadata.fetch("version"),
        "commit" => metadata.fetch("commit"),
        "build_date" => metadata.fetch("build_date"),
      }
    end

    def atomic_write(path, content)
      dir = File.dirname(path)
      Tempfile.create(["pm-formula-metadata-", ".json"], dir) do |tmp|
        tmp.write(content)
        tmp.flush
        tmp.fsync
        FileUtils.mv(tmp.path, path)
      end
    end
  end

  class CLI
    def initialize(argv, operations: Operations.new)
      @argv = argv.dup
      @operations = operations
    end

    def run
      command = @argv.shift
      fail Error, "command must be one of: plan, apply, check" unless %w[plan apply check].include?(command)

      output = case command
               when "plan"
                 options = parse_plan_options
                 @operations.plan(tag: options.fetch(:tag), metadata_out: options.fetch(:metadata_out))
               when "apply"
                 options = parse_apply_options
                 @operations.apply(
                   metadata_path: options.fetch(:metadata),
                   formula_path: options.fetch(:formula),
                   readme_path: options.fetch(:readme),
                   write: options.fetch(:write),
                 )
               when "check"
                 options = parse_check_options
                 @operations.check(
                   metadata_path: options.fetch(:metadata),
                   formula_path: options.fetch(:formula),
                   readme_path: options.fetch(:readme),
                 )
               end
      $stdout.write(output)
      0
    rescue Error, OptionParser::ParseError, KeyError => e
      $stderr.puts("pm_formula_bump: #{e.message}")
      1
    end

    private

    def parse_plan_options
      options = {}
      parser = OptionParser.new do |opts|
        opts.banner = "Usage: #{$PROGRAM_NAME} plan --tag <stable-tag> --metadata-out <path>"
        opts.on("--tag TAG") { |value| options[:tag] = value }
        opts.on("--metadata-out PATH") { |value| options[:metadata_out] = value }
      end
      parser.parse!(@argv)
      fail Error, "unexpected positional arguments: #{@argv.join(" ")}" unless @argv.empty?
      fail Error, "--tag is required" unless options[:tag]
      fail Error, "--metadata-out is required" unless options[:metadata_out]

      options
    end

    def parse_apply_options
      options = { write: false }
      parser = OptionParser.new do |opts|
        opts.banner = "Usage: #{$PROGRAM_NAME} apply --metadata <path> --formula Formula/pm.rb --readme README.md [--write]"
        opts.on("--metadata PATH") { |value| options[:metadata] = value }
        opts.on("--formula PATH") { |value| options[:formula] = value }
        opts.on("--readme PATH") { |value| options[:readme] = value }
        opts.on("--write") { options[:write] = true }
      end
      parser.parse!(@argv)
      fail Error, "unexpected positional arguments: #{@argv.join(" ")}" unless @argv.empty?
      %i[metadata formula readme].each { |key| fail Error, "--#{key} is required" unless options[key] }

      options
    end

    def parse_check_options
      options = {}
      parser = OptionParser.new do |opts|
        opts.banner = "Usage: #{$PROGRAM_NAME} check --metadata <path> --formula Formula/pm.rb --readme README.md"
        opts.on("--metadata PATH") { |value| options[:metadata] = value }
        opts.on("--formula PATH") { |value| options[:formula] = value }
        opts.on("--readme PATH") { |value| options[:readme] = value }
      end
      parser.parse!(@argv)
      fail Error, "unexpected positional arguments: #{@argv.join(" ")}" unless @argv.empty?
      %i[metadata formula readme].each { |key| fail Error, "--#{key} is required" unless options[key] }

      options
    end
  end
end

if $PROGRAM_NAME == __FILE__
  exit PMFormulaBump::CLI.new(ARGV).run
end
