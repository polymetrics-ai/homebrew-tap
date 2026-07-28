# frozen_string_literal: true

require "base64"
require "digest"
require "fileutils"
require "json"
require "minitest/autorun"
require "open3"
require "openssl"
require "tempfile"
require "tmpdir"

require_relative "../scripts/pm_release_verifier"

class PMReleaseVerifierTest < Minitest::Test
  ROOT = File.expand_path("..", __dir__)
  FORMULA_FIXTURES = File.join(ROOT, "test/fixtures/pm_formula_bump")
  VALID_METADATA = JSON.parse(File.read(File.join(FORMULA_FIXTURES, "v0.1.1-metadata.json"))).freeze
  VALID_RELEASE_ID = "361072189"
  VALID_SOURCE_RUN_ID = "30359194501"

  def setup
    @tmpdirs = []
  end

  def teardown
    @tmpdirs.each { |dir| FileUtils.rm_rf(dir) }
  end

  def test_verify_valid_release_writes_stable_outputs_and_does_not_mutate_current_files
    with_repo_fixture("current") do |repo|
      fixture = SyntheticRelease.new
      summary = verify(repo, fixture)

      assert_equal PMReleaseVerifier::VERIFICATION_SCHEMA, summary.fetch("schema")
      assert_equal VALID_METADATA, summary.fetch("metadata")
      assert_equal "dry-run: Formula/pm.rb and README.md already match metadata", summary.fetch("formula_dry_run")
      assert_equal 22, summary.dig("release_assets", "asset_count")
      assert_equal 11, summary.dig("release_assets", "signed_subject_count")
      assert_equal PMFormulaBump.stable_json(VALID_METADATA), File.read(fixture.metadata_path)
      assert_equal "", git(repo, "status", "--porcelain=v1", "--untracked-files=no")
    end
  end

  def test_verify_older_formula_reports_would_update_without_mutation
    with_repo_fixture("v0.1.0") do |repo|
      before_formula = File.read(File.join(repo, "Formula/pm.rb"))
      before_readme = File.read(File.join(repo, "README.md"))
      fixture = SyntheticRelease.new
      summary = verify(repo, fixture)

      assert_equal "dry-run: would update Formula/pm.rb and README.md", summary.fetch("formula_dry_run")
      assert_equal before_formula, File.read(File.join(repo, "Formula/pm.rb"))
      assert_equal before_readme, File.read(File.join(repo, "README.md"))
      assert_equal "", git(repo, "status", "--porcelain=v1", "--untracked-files=no")
    end
  end

  def test_rejects_invalid_untrusted_inputs
    invalid_cases = [
      { version: "v0.1.1" },
      { version: "0.1.1;echo pwned" },
      { version: "0.1.1-rc.1" },
      { dispatch_schema: "other/v1" },
      { source_repo: "attacker/cli" },
      { release_id: "123abc" },
      { source_run_id: "30359194501 && echo pwned" },
      { target_commitish_policy: "trust-release-field" },
    ]

    with_repo_fixture("current") do |repo|
      invalid_cases.each do |overrides|
        fixture = SyntheticRelease.new
        assert_raises(PMReleaseVerifier::Error, overrides.inspect) do
          verify(repo, fixture, **overrides)
        end
      end
    end
  end

  def test_rejects_release_id_tag_mismatch
    with_repo_fixture("current") do |repo|
      fixture = SyntheticRelease.new
      fixture.release_by_id_override = fixture.release.merge("id" => VALID_RELEASE_ID.to_i, "tag_name" => "v0.1.0")

      error = assert_raises(PMReleaseVerifier::Error) { verify(repo, fixture) }
      assert_match(/release returned by id tag_name does not match v0\.1\.1/, error.message)
    end
  end

  def test_rejects_planned_source_checksum_that_does_not_match_current_formula_metadata
    with_repo_fixture("current") do |repo|
      bad_metadata = VALID_METADATA.merge("source_sha256" => "a" * 64)
      fixture = SyntheticRelease.new(metadata: bad_metadata)

      error = assert_raises(PMFormulaBump::Error) { verify(repo, fixture) }
      assert_match(/same-version Formula\/pm\.rb drift/, error.message)
    end
  end

  def test_rejects_asset_set_mismatches
    mutators = {
      missing: ->(fixture) { fixture.remove_asset("pm_0.1.1_linux_amd64.tar.gz") },
      unexpected: ->(fixture) { fixture.add_unexpected_asset("pm_0.1.1_linux_amd64.tar.gz.old") },
      duplicate: ->(fixture) { fixture.duplicate_asset("checksums.txt.sigstore.json") },
      not_uploaded: ->(fixture) { fixture.set_asset_state("pm_0.1.1_windows_arm64.zip", "starter") },
    }

    with_repo_fixture("current") do |repo|
      mutators.each do |name, mutator|
        fixture = SyntheticRelease.new
        mutator.call(fixture)
        error = assert_raises(PMReleaseVerifier::Error, name.to_s) { verify(repo, fixture) }
        assert_match(/release asset inventory mismatch/, error.message)
      end
    end
  end

  def test_rejects_checksum_manifest_binding_failure
    with_repo_fixture("current") do |repo|
      fixture = SyntheticRelease.new(
        checksum_overrides: {
          "pm_0.1.1_linux_amd64.tar.gz" => "b" * 64,
        },
      )

      error = assert_raises(PMReleaseVerifier::Error) { verify(repo, fixture) }
      assert_match(/checksum manifest digest for pm_0\.1\.1_linux_amd64\.tar\.gz does not match/, error.message)
    end
  end

  def test_rejects_cosign_signature_failure
    with_repo_fixture("current") do |repo|
      fixture = SyntheticRelease.new
      fixture.corrupt_cosign_signature("pm_0.1.1_darwin_amd64.tar.gz")

      error = assert_raises(PMReleaseVerifier::Error) { verify(repo, fixture) }
      assert_match(/Cosign signature for pm_0\.1\.1_darwin_amd64\.tar\.gz did not verify/, error.message)
    end
  end

  def test_rejects_certificate_identity_failure
    with_repo_fixture("current") do |repo|
      fixture = SyntheticRelease.new(cert_repo: "attacker/cli")

      error = assert_raises(PMReleaseVerifier::Error) { verify(repo, fixture) }
      assert_match(/certificate subject identity is not the PM release workflow/, error.message)
    end
  end

  def test_rejects_github_artifact_attestation_failure
    with_repo_fixture("current") do |repo|
      fixture = SyntheticRelease.new
      fixture.remove_attestation("checksums.txt")

      error = assert_raises(PMReleaseVerifier::Error) { verify(repo, fixture) }
      assert_match(/missing GitHub artifact attestation for checksums\.txt/, error.message)
    end
  end

  def test_ignores_mutable_target_commitish_by_default_but_strict_policy_refuses_it
    with_repo_fixture("current") do |repo|
      fixture = SyntheticRelease.new(target_commitish: "main")
      assert_equal "ignore", verify(repo, fixture).fetch("target_commitish_policy")

      error = assert_raises(PMReleaseVerifier::Error) do
        verify(repo, fixture, target_commitish_policy: "require-full-sha")
      end
      assert_match(/target_commitish must be a full commit SHA/, error.message)
    end
  end

  def test_rerun_determinism
    with_repo_fixture("current") do |repo|
      fixture = SyntheticRelease.new
      first = verify(repo, fixture)
      first_metadata = File.read(fixture.metadata_path)
      first_verification = File.read(fixture.verification_path)

      second_fixture = SyntheticRelease.new
      second = verify(repo, second_fixture)

      assert_equal first, second
      assert_equal first_metadata, File.read(second_fixture.metadata_path)
      assert_equal first_verification, File.read(second_fixture.verification_path)
      assert_equal "", git(repo, "status", "--porcelain=v1", "--untracked-files=no")
    end
  end

  private

  class SyntheticRelease
    attr_accessor :release_by_id_override
    attr_reader :release, :asset_bytes, :attestations, :metadata_path, :verification_path, :tmpdir

    def initialize(metadata: VALID_METADATA, target_commitish: "main", cert_repo: PMReleaseVerifier::SOURCE_REPO,
                   checksum_overrides: {})
      @metadata = metadata
      @target_commitish = target_commitish
      @cert_repo = cert_repo
      @checksum_overrides = checksum_overrides
      @tmpdir = Dir.mktmpdir("pm-release-verifier-fixture-")
      @metadata_path = File.join(@tmpdir, "metadata.json")
      @verification_path = File.join(@tmpdir, "verification.json")
      @asset_bytes = {}
      @attestations = {}
      @asset_states = {}
      @key, @cert = build_certificate
      build_assets
      build_release
    end

    def remove_asset(name)
      release.fetch("assets").reject! { |asset| asset.fetch("name") == name }
    end

    def add_unexpected_asset(name)
      @asset_bytes[name] = "unexpected\n"
      release.fetch("assets") << asset_entry(name, @asset_bytes.fetch(name))
    end

    def duplicate_asset(name)
      original = release.fetch("assets").find { |asset| asset.fetch("name") == name }
      release.fetch("assets") << original.merge("id" => 99_999)
    end

    def set_asset_state(name, state)
      asset = release.fetch("assets").find { |entry| entry.fetch("name") == name }
      asset["state"] = state
    end

    def corrupt_cosign_signature(name)
      bundle_name = "#{name}#{PMReleaseVerifier::COSIGN_BUNDLE_SUFFIX}"
      bundle = JSON.parse(@asset_bytes.fetch(bundle_name))
      bundle["base64Signature"] = Base64.strict_encode64("not a valid signature")
      set_asset_bytes(bundle_name, "#{JSON.generate(bundle)}\n")
    end

    def remove_attestation(name)
      digest = digest_for(name)
      @attestations[digest] = { "attestations" => [] }
    end

    def digest_for(name)
      Digest::SHA256.hexdigest(@asset_bytes.fetch(name))
    end

    private

    def build_assets
      subject_names = PMReleaseVerifier.expected_subject_asset_names(@metadata.fetch("version"))
      subject_names.each do |name|
        @asset_bytes[name] = "synthetic bytes for #{name}\n"
      end

      checksum_lines = subject_names.map do |name|
        digest = @checksum_overrides.fetch(name, digest_for(name))
        "#{digest}  #{name}\n"
      end
      @asset_bytes[PMReleaseVerifier::CHECKSUMS_NAME] = checksum_lines.join

      signed_subjects = PMReleaseVerifier.signed_subject_names(@metadata.fetch("version"))
      attestation_subjects = signed_subjects.to_h do |name|
        [name, name == PMReleaseVerifier::CHECKSUMS_NAME ? digest_for(name) : @checksum_overrides.fetch(name, digest_for(name))]
      end
      attestation_bundle = attestation_bundle_for(attestation_subjects)
      signed_subjects.each do |name|
        digest = digest_for(name)
        @asset_bytes["#{name}#{PMReleaseVerifier::COSIGN_BUNDLE_SUFFIX}"] = "#{JSON.generate(cosign_bundle_for(name, digest))}\n"
        @attestations[digest] = { "attestations" => [{ "bundle" => attestation_bundle }] }
      end
    end

    def build_release
      @release = {
        "id" => VALID_RELEASE_ID.to_i,
        "tag_name" => @metadata.fetch("tag"),
        "name" => @metadata.fetch("tag"),
        "draft" => false,
        "prerelease" => false,
        "published_at" => "2026-07-28T12:29:55Z",
        "target_commitish" => @target_commitish,
        "assets" => PMReleaseVerifier.expected_release_asset_names(@metadata.fetch("version")).each_with_index.map do |name, index|
          asset_entry(name, @asset_bytes.fetch(name), id: index + 1)
        end,
      }
    end

    def asset_entry(name, bytes, id: 99_001)
      {
        "id" => id,
        "name" => name,
        "state" => "uploaded",
        "digest" => "sha256:#{Digest::SHA256.hexdigest(bytes)}",
      }
    end

    def set_asset_bytes(name, bytes)
      @asset_bytes[name] = bytes
      asset = release.fetch("assets").find { |entry| entry.fetch("name") == name }
      asset["digest"] = "sha256:#{Digest::SHA256.hexdigest(bytes)}" if asset
    end

    def build_certificate
      key = OpenSSL::PKey::RSA.new(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      cert.subject = OpenSSL::X509::Name.parse("/CN=synthetic")
      cert.issuer = OpenSSL::X509::Name.parse("/O=sigstore.dev/CN=sigstore-intermediate")
      cert.public_key = key.public_key
      cert.not_before = Time.utc(2026, 7, 28, 12, 39, 0)
      cert.not_after = Time.utc(2026, 7, 28, 12, 49, 0)
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = cert
      factory.issuer_certificate = cert
      identity = "https://github.com/#{@cert_repo}/.github/workflows/release.yml@refs/heads/main"
      cert.add_extension(factory.create_extension("subjectAltName", "URI:#{identity}", true))
      cert.add_extension(utf8_extension(PMReleaseVerifier::SIGSTORE_OIDS.fetch(:issuer), PMReleaseVerifier::GITHUB_OIDC_ISSUER))
      cert.add_extension(utf8_extension(PMReleaseVerifier::SIGSTORE_OIDS.fetch(:event_name), "push"))
      cert.add_extension(utf8_extension(PMReleaseVerifier::SIGSTORE_OIDS.fetch(:commit_sha), @metadata.fetch("commit")))
      cert.add_extension(utf8_extension(PMReleaseVerifier::SIGSTORE_OIDS.fetch(:workflow_name), PMReleaseVerifier::RELEASE_WORKFLOW_NAME))
      cert.add_extension(utf8_extension(PMReleaseVerifier::SIGSTORE_OIDS.fetch(:repository), @cert_repo))
      cert.add_extension(utf8_extension(PMReleaseVerifier::SIGSTORE_OIDS.fetch(:ref), "refs/heads/main"))
      cert.add_extension(utf8_extension(PMReleaseVerifier::SIGSTORE_OIDS.fetch(:run_url), "https://github.com/#{@cert_repo}/actions/runs/#{VALID_SOURCE_RUN_ID}/attempts/1"))
      cert.sign(key, OpenSSL::Digest::SHA256.new)
      [key, cert]
    end

    def utf8_extension(oid, value)
      OpenSSL::X509::Extension.new(oid, OpenSSL::ASN1::UTF8String(value).to_der, false)
    end

    def cosign_bundle_for(name, digest)
      bytes = @asset_bytes.fetch(name)
      signature = @key.sign(OpenSSL::Digest::SHA256.new, bytes)
      signature_b64 = Base64.strict_encode64(signature)
      rekor_body = {
        "apiVersion" => "0.0.1",
        "kind" => "hashedrekord",
        "spec" => {
          "data" => { "hash" => { "algorithm" => "sha256", "value" => digest } },
          "signature" => { "content" => signature_b64 },
        },
      }
      {
        "base64Signature" => signature_b64,
        "cert" => Base64.strict_encode64(@cert.to_pem),
        "rekorBundle" => {
          "Payload" => {
            "body" => Base64.strict_encode64(JSON.generate(rekor_body)),
          },
        },
      }
    end

    def attestation_bundle_for(subjects)
      payload = JSON.generate(
        "_type" => PMReleaseVerifier::IN_TOTO_STATEMENT_TYPE,
        "subject" => subjects.map { |name, digest| { "name" => name, "digest" => { "sha256" => digest } } },
        "predicateType" => PMReleaseVerifier::SLSA_PROVENANCE_TYPE,
        "predicate" => { "buildDefinition" => {} },
      )
      payload_type = PMReleaseVerifier::ATTESTATION_PAYLOAD_TYPE
      signature = @key.sign(OpenSSL::Digest::SHA256.new, PMReleaseVerifier.dsse_pae(payload_type, payload))
      {
        "mediaType" => PMReleaseVerifier::ATTESTATION_BUNDLE_MEDIA_TYPE,
        "verificationMaterial" => {
          "certificate" => { "rawBytes" => Base64.strict_encode64(@cert.to_der) },
        },
        "dsseEnvelope" => {
          "payload" => Base64.strict_encode64(payload),
          "payloadType" => payload_type,
          "signatures" => [{ "sig" => Base64.strict_encode64(signature) }],
        },
      }
    end
  end

  class FakeClient
    def initialize(fixture)
      @fixture = fixture
    end

    def release_by_tag(tag)
      fail PMReleaseVerifier::Error, "unexpected tag #{tag}" unless tag == VALID_METADATA.fetch("tag")

      deep_copy(@fixture.release)
    end

    def release_by_id(release_id)
      fail PMReleaseVerifier::Error, "unexpected release id #{release_id}" unless release_id == VALID_RELEASE_ID

      deep_copy(@fixture.release_by_id_override || @fixture.release)
    end

    def tag_ref(tag)
      fail PMReleaseVerifier::Error, "unexpected tag ref #{tag}" unless tag == VALID_METADATA.fetch("tag")

      { "object" => { "type" => "commit", "sha" => @fixture_metadata.fetch("commit") } }
    end

    def tag_object(_sha)
      raise PMReleaseVerifier::Error, "annotated tags are not used in these fixtures"
    end

    def commit(commitish)
      fail PMReleaseVerifier::Error, "unexpected commit #{commitish}" unless commitish == @fixture_metadata.fetch("commit")

      {
        "sha" => @fixture_metadata.fetch("commit"),
        "commit" => { "committer" => { "date" => @fixture_metadata.fetch("build_date") } },
      }
    end

    def download_archive_sha256(source_url, tag)
      fail PMReleaseVerifier::Error, "unexpected source url #{source_url}" unless source_url == @fixture_metadata.fetch("source_url")
      fail PMReleaseVerifier::Error, "unexpected source tag #{tag}" unless tag == @fixture_metadata.fetch("tag")

      @fixture_metadata.fetch("source_sha256")
    end

    def download_release_asset(name, tag)
      fail PMReleaseVerifier::Error, "unexpected release asset tag #{tag}" unless tag == @fixture_metadata.fetch("tag")

      bytes = @fixture.asset_bytes.fetch(name)
      Tempfile.create(["pm-release-verifier-test-", "-#{name}"]) do |file|
        file.binmode
        file.write(bytes)
        file.flush
        file.rewind
        yield file.path
      end
    end

    def attestations_by_digest(digest)
      deep_copy(@fixture.attestations.fetch(digest, { "attestations" => [] }))
    end

    def fixture_metadata=(metadata)
      @fixture_metadata = metadata
    end

    private

    def deep_copy(object)
      JSON.parse(JSON.generate(object))
    end
  end

  def verify(repo, fixture, dispatch_schema: PMReleaseVerifier::DISPATCH_SCHEMA,
             source_repo: PMReleaseVerifier::SOURCE_REPO, version: VALID_METADATA.fetch("version"),
             release_id: VALID_RELEASE_ID, source_run_id: VALID_SOURCE_RUN_ID,
             target_commitish_policy: "ignore")
    @tmpdirs << fixture.tmpdir unless @tmpdirs.include?(fixture.tmpdir)
    client = FakeClient.new(fixture)
    client.fixture_metadata = fixture.instance_variable_get(:@metadata)
    PMReleaseVerifier::Operations.new(root: repo, client: client).verify(
      dispatch_schema: dispatch_schema,
      source_repo: source_repo,
      version: version,
      release_id: release_id,
      source_run_id: source_run_id,
      target_commitish_policy: target_commitish_policy,
      metadata_out: fixture.metadata_path,
      verification_out: fixture.verification_path,
      formula_path: "Formula/pm.rb",
      readme_path: "README.md",
    )
  end

  def with_repo_fixture(name)
    Dir.mktmpdir("pm-release-verifier-repo-") do |repo|
      FileUtils.mkdir_p(File.join(repo, "Formula"))
      FileUtils.cp(File.join(FORMULA_FIXTURES, name, "Formula/pm.rb"), File.join(repo, "Formula/pm.rb"))
      FileUtils.cp(File.join(FORMULA_FIXTURES, name, "README.md"), File.join(repo, "README.md"))
      git(repo, "init", "--quiet")
      git(repo, "add", "Formula/pm.rb", "README.md")
      git(repo, "-c", "user.email=test@example.com", "-c", "user.name=Test", "commit", "--quiet", "-m", "initial")
      yield repo
    end
  end

  def git(repo, *args)
    stdout, stderr, status = Open3.capture3("git", "-C", repo, *args)
    assert status.success?, stderr
    stdout
  end
end
