# frozen_string_literal: true

require "fileutils"
require "json"
require "minitest/autorun"
require "open3"
require "tmpdir"

require_relative "../scripts/pm_formula_bump"

class PMFormulaBumpTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  FIXTURES = File.join(ROOT, "test/fixtures/pm_formula_bump")
  VALID_METADATA = JSON.parse(File.read(File.join(FIXTURES, "v0.1.1-metadata.json"))).freeze

  def setup
    @tmpdirs = []
  end

  def teardown
    @tmpdirs.each { |dir| FileUtils.rm_rf(dir) }
  end

  class FakeClient
    attr_reader :commit_requests, :download_requests

    def initialize(metadata = VALID_METADATA, release_overrides: {}, tag_type: "commit")
      @metadata = metadata
      @release_overrides = release_overrides
      @tag_type = tag_type
      @commit_requests = []
      @download_requests = []
    end

    def release_by_tag(tag)
      {
        "tag_name" => tag,
        "draft" => false,
        "prerelease" => false,
        "published_at" => "2026-07-28T12:29:55Z",
        "target_commitish" => @metadata.fetch("commit"),
      }.merge(@release_overrides)
    end

    def tag_ref(_tag)
      if @tag_type == "tag"
        { "object" => { "type" => "tag", "sha" => "1111111111111111111111111111111111111111" } }
      else
        { "object" => { "type" => "commit", "sha" => @metadata.fetch("commit") } }
      end
    end

    def tag_object(_sha)
      { "object" => { "type" => "commit", "sha" => @metadata.fetch("commit") } }
    end

    def commit(commitish)
      @commit_requests << commitish
      fail PMFormulaBump::Error, "unexpected commit lookup: #{commitish}" unless commitish == @metadata.fetch("commit")

      {
        "sha" => @metadata.fetch("commit"),
        "commit" => { "committer" => { "date" => @metadata.fetch("build_date") } },
      }
    end

    def download_archive_sha256(source_url, tag)
      @download_requests << [source_url, tag]
      @metadata.fetch("source_sha256")
    end
  end

  def test_check_accepts_v0_1_1_current_baseline
    with_repo_fixture("current") do |repo|
      output = operations(repo).check(
        metadata_path: metadata_file(VALID_METADATA),
        formula_path: "Formula/pm.rb",
        readme_path: "README.md",
      )

      assert_equal "Formula/pm.rb and README.md match metadata\n", output
    end
  end

  def test_plan_writes_stable_metadata_outside_repo_without_tracked_changes
    with_repo_fixture("current") do |repo|
      fake_client = FakeClient.new
      planner = PMFormulaBump::Planner.new(client: fake_client)
      metadata_path = tmp_metadata_path

      first = operations(repo, planner: planner).plan(tag: "v0.1.1", metadata_out: metadata_path)
      second_path = tmp_metadata_path
      second = operations(repo, planner: PMFormulaBump::Planner.new(client: FakeClient.new))
               .plan(tag: "v0.1.1", metadata_out: second_path)

      assert_equal stable_metadata_json(VALID_METADATA), first
      assert_equal first, second
      assert_equal first, File.read(metadata_path)
      assert_equal first, File.read(second_path)
      assert_equal [[VALID_METADATA.fetch("source_url"), "v0.1.1"]], fake_client.download_requests
      assert_equal "", git(repo, "status", "--porcelain=v1", "--untracked-files=no")
    end
  end

  def test_plan_supports_annotated_tags_by_resolving_to_commit
    client = FakeClient.new(VALID_METADATA, tag_type: "tag")
    metadata = PMFormulaBump::Planner.new(client: client).plan("v0.1.1")

    assert_equal VALID_METADATA.fetch("commit"), metadata.fetch("commit")
  end

  def test_plan_uses_tag_commit_not_branch_valued_release_target
    client = FakeClient.new(VALID_METADATA, release_overrides: { "target_commitish" => "main" })
    metadata = PMFormulaBump::Planner.new(client: client).plan("v0.1.1")

    assert_equal VALID_METADATA.fetch("commit"), metadata.fetch("commit")
    assert_equal VALID_METADATA.fetch("build_date"), metadata.fetch("build_date")
    assert_equal [VALID_METADATA.fetch("commit")], client.commit_requests
  end

  def test_apply_without_write_is_dry_run_and_does_not_change_files
    with_repo_fixture("v0.1.0") do |repo|
      before_formula = File.read(File.join(repo, "Formula/pm.rb"))
      before_readme = File.read(File.join(repo, "README.md"))

      output = operations(repo).apply(
        metadata_path: metadata_file(VALID_METADATA),
        formula_path: "Formula/pm.rb",
        readme_path: "README.md",
        write: false,
      )

      assert_equal "dry-run: would update Formula/pm.rb and README.md\n", output
      assert_equal before_formula, File.read(File.join(repo, "Formula/pm.rb"))
      assert_equal before_readme, File.read(File.join(repo, "README.md"))
      assert_raises(PMFormulaBump::Error) do
        operations(repo).check(
          metadata_path: metadata_file(VALID_METADATA),
          formula_path: "Formula/pm.rb",
          readme_path: "README.md",
        )
      end
    end
  end

  def test_apply_write_updates_formula_readme_and_is_repeatedly_idempotent
    with_repo_fixture("v0.1.0") do |repo|
      2.times do
        operations(repo).apply(
          metadata_path: metadata_file(VALID_METADATA),
          formula_path: "Formula/pm.rb",
          readme_path: "README.md",
          write: true,
        )
      end

      assert_equal File.read(File.join(FIXTURES, "current/Formula/pm.rb")), File.read(File.join(repo, "Formula/pm.rb"))
      assert_equal File.read(File.join(FIXTURES, "current/README.md")), File.read(File.join(repo, "README.md"))
      assert_equal "", unexpected_status(repo)
      assert_equal "Formula/pm.rb and README.md match metadata\n",
                   operations(repo).check(
                     metadata_path: metadata_file(VALID_METADATA),
                     formula_path: "Formula/pm.rb",
                     readme_path: "README.md",
                   )
    end
  end

  def test_current_version_apply_is_idempotent
    with_repo_fixture("current") do |repo|
      3.times do
        assert_equal "Formula/pm.rb and README.md already match metadata\n",
                     operations(repo).apply(
                       metadata_path: metadata_file(VALID_METADATA),
                       formula_path: "Formula/pm.rb",
                       readme_path: "README.md",
                       write: true,
                     )
      end

      assert_equal "", git(repo, "status", "--porcelain=v1", "--untracked-files=no")
    end
  end

  def test_rejects_malformed_tags
    [
      "",
      "0.1.1",
      "v01.2.3",
      "v1.02.3",
      "v1.2.03",
      "v1.2",
      "v1.2.3-rc.1",
      "v1.2.3+build.1",
      "v1.2.3/evil",
      "--v1.2.3",
    ].each do |tag|
      assert_raises(PMFormulaBump::Error, "#{tag.inspect} should be rejected") do
        PMFormulaBump.validate_stable_tag!(tag)
      end
    end
  end

  def test_rejects_malformed_metadata
    malformed = [
      VALID_METADATA.merge("schema" => "other/v1"),
      VALID_METADATA.merge("source_repo" => "elsewhere/cli"),
      VALID_METADATA.merge("tag" => "v0.1.1-rc.1"),
      VALID_METADATA.merge("version" => "0.1.2"),
      VALID_METADATA.merge("source_url" => "https://example.com/archive.tar.gz"),
      VALID_METADATA.merge("source_sha256" => VALID_METADATA.fetch("source_sha256").upcase),
      VALID_METADATA.merge("commit" => VALID_METADATA.fetch("commit").upcase),
      VALID_METADATA.merge("build_date" => "2026-07-28T12:29:42+00:00"),
      VALID_METADATA.merge("extra" => "not allowed"),
    ]

    malformed.each do |metadata|
      assert_raises(PMFormulaBump::Error) { PMFormulaBump.metadata_from_hash(metadata) }
    end
  end

  def test_check_reports_mismatched_source_sha_commit_and_date
    {
      "source_sha256" => "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "commit" => "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "build_date" => "2026-07-28T12:29:43Z",
    }.each do |field, value|
      with_repo_fixture("current") do |repo|
        error = assert_raises(PMFormulaBump::Error) do
          operations(repo).check(
            metadata_path: metadata_file(VALID_METADATA.merge(field => value)),
            formula_path: "Formula/pm.rb",
            readme_path: "README.md",
          )
        end

        assert_match(/drift/, error.message)
      end
    end
  end

  def test_check_reports_formula_and_readme_drift
    with_repo_fixture("current") do |repo|
      formula = File.join(repo, "Formula/pm.rb")
      File.write(formula, File.read(formula).sub(VALID_METADATA.fetch("source_sha256"), "a" * 64))

      error = assert_raises(PMFormulaBump::Error) do
        operations(repo).check(
          metadata_path: metadata_file(VALID_METADATA),
          formula_path: "Formula/pm.rb",
          readme_path: "README.md",
        )
      end
      assert_match(/Formula\/pm\.rb drift/, error.message)
    end

    with_repo_fixture("current") do |repo|
      readme = File.join(repo, "README.md")
      File.write(readme, File.read(readme).sub(VALID_METADATA.fetch("commit"), "b" * 40))

      error = assert_raises(PMFormulaBump::Error) do
        operations(repo).check(
          metadata_path: metadata_file(VALID_METADATA),
          formula_path: "Formula/pm.rb",
          readme_path: "README.md",
        )
      end
      assert_match(/README\.md drift/, error.message)
    end
  end

  def test_apply_rejects_downgrade_and_same_version_metadata_conflict
    with_repo_fixture("current") do |repo|
      assert_raises(PMFormulaBump::Error) do
        operations(repo).apply(
          metadata_path: metadata_file(v0_1_0_metadata),
          formula_path: "Formula/pm.rb",
          readme_path: "README.md",
          write: true,
        )
      end
    end

    with_repo_fixture("current") do |repo|
      conflict = VALID_METADATA.merge("source_sha256" => "a" * 64)
      error = assert_raises(PMFormulaBump::Error) do
        operations(repo).apply(
          metadata_path: metadata_file(conflict),
          formula_path: "Formula/pm.rb",
          readme_path: "README.md",
          write: true,
        )
      end

      assert_match(/same-version Formula\/pm\.rb drift/, error.message)
    end
  end

  def test_apply_rejects_unexpected_tracked_file_changes
    with_repo_fixture("current") do |repo|
      FileUtils.mkdir_p(File.join(repo, "docs"))
      File.write(File.join(repo, "docs/notes.md"), "tracked\n")
      git(repo, "add", "docs/notes.md")
      git(repo, "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "-m", "add notes")
      File.write(File.join(repo, "docs/notes.md"), "dirty\n")

      error = assert_raises(PMFormulaBump::Error) do
        operations(repo).apply(
          metadata_path: metadata_file(VALID_METADATA),
          formula_path: "Formula/pm.rb",
          readme_path: "README.md",
          write: true,
        )
      end

      assert_match(/unexpected tracked-file changes/, error.message)
    end
  end

  def test_rejects_paths_outside_allowlist_and_metadata_inside_repo
    with_repo_fixture("current") do |repo|
      assert_raises(PMFormulaBump::Error) do
        operations(repo).check(
          metadata_path: metadata_file(VALID_METADATA),
          formula_path: "README.md",
          readme_path: "README.md",
        )
      end

      inside_repo_metadata = File.join(repo, "metadata.json")
      File.write(inside_repo_metadata, stable_metadata_json(VALID_METADATA))
      assert_raises(PMFormulaBump::Error) do
        operations(repo).check(
          metadata_path: inside_repo_metadata,
          formula_path: "Formula/pm.rb",
          readme_path: "README.md",
        )
      end

      assert_raises(PMFormulaBump::Error) do
        operations(repo).plan(tag: "v0.1.1", metadata_out: inside_repo_metadata)
      end
    end
  end

  private

  def operations(repo, planner: PMFormulaBump::Planner.new(client: FakeClient.new))
    PMFormulaBump::Operations.new(root: repo, planner: planner)
  end

  def with_repo_fixture(name)
    Dir.mktmpdir("pm-formula-bump-repo-") do |repo|
      FileUtils.mkdir_p(File.join(repo, "Formula"))
      FileUtils.cp(File.join(FIXTURES, name, "Formula/pm.rb"), File.join(repo, "Formula/pm.rb"))
      FileUtils.cp(File.join(FIXTURES, name, "README.md"), File.join(repo, "README.md"))
      git(repo, "init", "--quiet")
      git(repo, "add", "Formula/pm.rb", "README.md")
      git(repo, "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "--quiet", "-m", "initial")
      yield repo
    end
  end

  def metadata_file(metadata)
    path = tmp_metadata_path
    File.write(path, stable_metadata_json(metadata))
    path
  end

  def tmp_metadata_path
    dir = Dir.mktmpdir("pm-formula-bump-metadata-")
    @tmpdirs << dir
    File.join(dir, "metadata.json")
  end

  def stable_metadata_json(metadata)
    PMFormulaBump.stable_json(PMFormulaBump.metadata_from_hash(metadata))
  end

  def v0_1_0_metadata
    {
      "schema" => "pm-homebrew-formula-metadata/v1",
      "source_repo" => "polymetrics-ai/cli",
      "tag" => "v0.1.0",
      "version" => "0.1.0",
      "source_url" => "https://github.com/polymetrics-ai/cli/archive/refs/tags/v0.1.0.tar.gz",
      "source_sha256" => "c947c513a2e192b5b730070ef2052e14eadacd199edc4d3051943a65c27050ea",
      "commit" => "6de947ca89946a461b5c4c5b0daadf3a0f0f6ad6",
      "build_date" => "2026-07-27T11:29:34Z",
    }
  end

  def unexpected_status(repo)
    git(repo, "status", "--porcelain=v1", "--untracked-files=no").lines
       .reject { |line| line.include?("Formula/pm.rb") || line.include?("README.md") }
       .join
  end

  def git(repo, *args)
    stdout, stderr, status = Open3.capture3("git", "-C", repo, *args)
    assert status.success?, stderr
    stdout
  end
end
