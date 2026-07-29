#!/usr/bin/env ruby
# frozen_string_literal: true

require "base64"
require "digest"
require "fileutils"
require "json"
require "net/http"
require "open3"
require "openssl"
require "optparse"
require "tempfile"
require "time"
require "uri"

require_relative "pm_formula_bump"

module PMReleaseVerifier
  class Error < PMFormulaBump::Error; end

  DISPATCH_SCHEMA = "pm-homebrew-release-dry-run/v1"
  VERIFICATION_SCHEMA = "pm-homebrew-release-verification/v1"
  SOURCE_REPO = PMFormulaBump::SOURCE_REPO
  RELEASE_WORKFLOW_IDENTITY_PREFIX = "https://github.com/#{SOURCE_REPO}/.github/workflows/release.yml@"
  RELEASE_WORKFLOW_NAME = "Release"
  GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
  TARGET_COMMITISH_POLICIES = %w[ignore require-full-sha].freeze
  SHA256_DIGEST_PATTERN = /\Asha256:([0-9a-f]{64})\z/
  DECIMAL_PATTERN = /\A[1-9][0-9]*\z/
  SAFE_ASSET_NAME_PATTERN = /\A[A-Za-z0-9._-]+\z/
  COSIGN_BUNDLE_SUFFIX = ".sigstore.json"
  CHECKSUMS_NAME = "checksums.txt"
  ATTESTATION_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
  ATTESTATION_PAYLOAD_TYPE = "application/vnd.in-toto+json"
  IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
  SLSA_PROVENANCE_TYPE = "https://slsa.dev/provenance/v1"

  SIGSTORE_OIDS = {
    issuer: "1.3.6.1.4.1.57264.1.1",
    event_name: "1.3.6.1.4.1.57264.1.2",
    commit_sha: "1.3.6.1.4.1.57264.1.3",
    workflow_name: "1.3.6.1.4.1.57264.1.4",
    repository: "1.3.6.1.4.1.57264.1.5",
    ref: "1.3.6.1.4.1.57264.1.6",
    run_url: "1.3.6.1.4.1.57264.1.21",
  }.freeze

  module_function

  def validate_stable_version!(version)
    fail Error, "version is required" if version.nil?
    fail Error, "version must be a string" unless version.is_a?(String)
    fail Error, "version is required" if version.empty?
    fail Error, "version must not look like an option" if version.start_with?("-")

    tag = "v#{version}"
    PMFormulaBump.validate_stable_tag!(tag)
    fail Error, "version must be stable semver without leading v" unless PMFormulaBump.version_from_tag(tag) == version

    version
  rescue PMFormulaBump::Error => e
    raise Error, e.message.sub("tag", "version")
  end

  def tag_for_version(version)
    "v#{validate_stable_version!(version)}"
  end

  def expected_subject_asset_names(version)
    version = validate_stable_version!(version)

    [
      "pm_#{version}_darwin_amd64.tar.gz",
      "pm_#{version}_darwin_arm64.tar.gz",
      "pm_#{version}_linux_aarch64.rpm",
      "pm_#{version}_linux_amd64.deb",
      "pm_#{version}_linux_amd64.tar.gz",
      "pm_#{version}_linux_arm64.deb",
      "pm_#{version}_linux_arm64.tar.gz",
      "pm_#{version}_linux_x86_64.rpm",
      "pm_#{version}_windows_amd64.zip",
      "pm_#{version}_windows_arm64.zip",
    ].freeze
  end

  def signed_subject_names(version)
    [CHECKSUMS_NAME, *expected_subject_asset_names(version)].freeze
  end

  def expected_release_asset_names(version)
    signed_subject_names(version).flat_map { |name| [name, "#{name}#{COSIGN_BUNDLE_SUFFIX}"] }.freeze
  end

  def certificate_policies(tag)
    tag = PMFormulaBump.validate_stable_tag!(tag)

    ["refs/heads/main", "refs/tags/#{tag}"].map do |ref|
      {
        ref: ref,
        identity: "#{RELEASE_WORKFLOW_IDENTITY_PREFIX}#{ref}",
      }
    end
  end

  def validate_decimal!(value, description, required: false)
    fail Error, "#{description} is required" if required && value.nil?
    return nil if value.nil?
    fail Error, "#{description} must be a string" unless value.is_a?(String)
    fail Error, "#{description} is required" if required && value.empty?
    return nil if value.empty?

    fail Error, "#{description} must not look like an option" if value.start_with?("-")
    fail Error, "#{description} must be a positive decimal integer" unless DECIMAL_PATTERN.match?(value)

    value
  end

  def validate_string!(value, description, expected: nil, required: true)
    fail Error, "#{description} is required" if required && value.nil?
    return nil if value.nil?
    fail Error, "#{description} must be a string" unless value.is_a?(String)
    fail Error, "#{description} is required" if required && value.empty?
    return nil if value.empty?

    fail Error, "#{description} must not look like an option" if value.start_with?("-")
    fail Error, "#{description} must be #{expected}" if expected && value != expected

    value
  end

  def parse_json_object(bytes, description)
    json = JSON.parse(bytes)
    fail Error, "#{description} must be a JSON object" unless json.is_a?(Hash)

    json
  rescue JSON::ParserError
    raise Error, "#{description} is not valid JSON"
  end

  def parse_json_array(bytes, description)
    json = JSON.parse(bytes)
    fail Error, "#{description} must be a JSON array" unless json.is_a?(Array)

    json
  rescue JSON::ParserError
    raise Error, "#{description} is not valid JSON"
  end

  def parse_x509_certificate(bytes, description)
    OpenSSL::X509::Certificate.new(bytes)
  rescue OpenSSL::X509::CertificateError => e
    raise Error, "#{description} could not be parsed: #{e.message}"
  end

  def certificate_from_sigstore_bundle(bundle, description)
    fail Error, "#{description} must be a JSON object" unless bundle.is_a?(Hash)

    parse_x509_certificate(sigstore_bundle_certificate_bytes(bundle, description), description)
  end

  def sigstore_bundle_certificate_bytes(bundle, description)
    if bundle["cert"].is_a?(String) && !bundle["cert"].empty?
      return strict_base64_decode(bundle["cert"], description)
    end

    raw_bytes = bundle.dig("verificationMaterial", "certificate", "rawBytes")
    return strict_base64_decode(raw_bytes, description) if raw_bytes.is_a?(String) && !raw_bytes.empty?

    chain = bundle.dig("verificationMaterial", "x509CertificateChain", "certificates")
    chain_cert = chain.first if chain.is_a?(Array) && chain.first.is_a?(Hash)
    raw_bytes = chain_cert&.fetch("rawBytes", nil)
    return strict_base64_decode(raw_bytes, description) if raw_bytes.is_a?(String) && !raw_bytes.empty?

    fail Error, "#{description} is missing certificate bytes"
  end

  def strict_base64_decode(value, description)
    fail Error, "#{description} must be a string" unless value.is_a?(String) && !value.empty?

    Base64.strict_decode64(value)
  rescue ArgumentError
    raise Error, "#{description} is not valid base64"
  end

  def dsse_pae(payload_type, payload)
    [
      "DSSEv1",
      payload_type.bytesize.to_s,
      payload_type,
      payload.bytesize.to_s,
      payload,
    ].join(" ")
  end

  class GitHubClient < PMFormulaBump::GitHubClient
    RELEASE_DOWNLOAD_HOSTS = %w[
      github.com
      objects.githubusercontent.com
      release-assets.githubusercontent.com
    ].freeze

    def release_by_id(release_id)
      api_json("/repos/#{SOURCE_REPO}/releases/#{release_id}")
    end

    def download_release_asset(name, tag)
      fail Error, "release asset name is unsafe: #{name.inspect}" unless SAFE_ASSET_NAME_PATTERN.match?(name)
      PMFormulaBump.validate_stable_tag!(tag)

      Tempfile.create(["pm-release-asset-", "-#{name}"]) do |file|
        file.binmode
        download_release_url_to_file(URI("https://github.com/#{SOURCE_REPO}/releases/download/#{tag}/#{name}"), file)
        file.flush
        file.rewind
        yield file.path
      end
    end

    private

    def download_release_url_to_file(uri, file, redirects_remaining = 5)
      fail Error, "too many release asset redirects" if redirects_remaining.negative?
      fail Error, "release asset URL must use https" unless uri.scheme == "https"
      fail Error, "unexpected release asset host: #{uri.host}" unless RELEASE_DOWNLOAD_HOSTS.include?(uri.host)

      response = download_release_response(uri, file)
      case response
      when Net::HTTPRedirection
        location = response["location"]
        fail Error, "release asset redirect missing location" if location.nil? || location.empty?

        download_release_url_to_file(URI.join(uri, location), file, redirects_remaining - 1)
      when Net::HTTPSuccess
        nil
      else
        fail Error, "release asset download failed for #{File.basename(uri.path)}: HTTP #{response.code}"
      end
    end

    def download_release_response(uri, file)
      response = nil
      Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
        http.request(build_request(uri)) do |http_response|
          response = http_response
          http_response.read_body { |chunk| file.write(chunk) } if http_response.is_a?(Net::HTTPSuccess)
        end
      end
      response
    end
  end

  class ExternalVerifier
    def initialize(cosign: "cosign", gh: "gh")
      @cosign = cosign
      @gh = gh
    end

    def verify_cosign_blob!(subject_path:, bundle_path:, expected_name:, tag:, commit:)
      with_certificate_policy(tag, "Cosign verification for #{expected_name}") do |policy|
        run_command(
          [
            @cosign,
            "verify-blob",
            "--bundle",
            bundle_path,
            "--certificate-identity",
            policy.fetch(:identity),
            "--certificate-oidc-issuer",
            GITHUB_OIDC_ISSUER,
            "--certificate-github-workflow-name",
            RELEASE_WORKFLOW_NAME,
            "--certificate-github-workflow-repository",
            SOURCE_REPO,
            "--certificate-github-workflow-sha",
            commit,
            "--certificate-github-workflow-ref",
            policy.fetch(:ref),
            subject_path,
          ],
        )
      end
    end

    def verify_github_attestation!(subject_path:, expected_name:, tag:, commit:)
      with_certificate_policy(tag, "GitHub artifact attestation verification for #{expected_name}") do |policy|
        output = run_command(
          [
            @gh,
            "attestation",
            "verify",
            subject_path,
            "--repo",
            SOURCE_REPO,
            "--cert-identity",
            policy.fetch(:identity),
            "--cert-oidc-issuer",
            GITHUB_OIDC_ISSUER,
            "--source-digest",
            commit,
            "--source-ref",
            policy.fetch(:ref),
            "--predicate-type",
            SLSA_PROVENANCE_TYPE,
            "--deny-self-hosted-runners",
            "--limit",
            "2",
            "--format",
            "json",
          ],
        )
        PMReleaseVerifier.parse_json_array(output, "GitHub artifact attestation verification output for #{expected_name}")
      end
    end

    private

    def with_certificate_policy(tag, description)
      errors = []
      PMReleaseVerifier.certificate_policies(tag).each do |policy|
        begin
          return yield policy
        rescue Error => e
          errors << "#{policy.fetch(:ref)}: #{e.message}"
        end
      end

      fail Error, "#{description} failed for all approved refs (#{errors.join("; ")})"
    end

    def run_command(argv)
      stdout, stderr, status = Open3.capture3(*argv)
      return stdout if status.success?

      detail = redacted_output(stderr.empty? ? stdout : stderr)
      suffix = detail.empty? ? "" : ": #{detail}"
      fail Error, "#{argv.fetch(0)} #{argv.fetch(1)} failed#{suffix}"
    rescue Errno::ENOENT
      raise Error, "#{argv.fetch(0)} is required for release verification"
    end

    def redacted_output(text)
      redacted = text.to_s
      %w[GITHUB_TOKEN GH_TOKEN].each do |name|
        token = ENV[name]
        redacted = redacted.gsub(token, "[REDACTED]") if token && !token.empty?
      end
      redacted.lines.first(5).join.strip
    end
  end

  class Inputs
    def initialize(dispatch_schema:, source_repo:, version:, release_id:, source_run_id:, target_commitish_policy:)
      @dispatch_schema = PMReleaseVerifier.validate_string!(
        dispatch_schema,
        "dispatch_schema",
        expected: DISPATCH_SCHEMA,
      )
      @source_repo = PMReleaseVerifier.validate_string!(source_repo, "source_repo", expected: SOURCE_REPO)
      @version = PMReleaseVerifier.validate_stable_version!(version)
      @tag = PMReleaseVerifier.tag_for_version(@version)
      @release_id = PMReleaseVerifier.validate_decimal!(release_id, "release_id")
      @source_run_id = PMReleaseVerifier.validate_decimal!(source_run_id, "source_run_id")
      @target_commitish_policy = PMReleaseVerifier.validate_string!(
        target_commitish_policy,
        "target_commitish_policy",
      )
      unless TARGET_COMMITISH_POLICIES.include?(@target_commitish_policy)
        fail Error, "target_commitish_policy must be one of: #{TARGET_COMMITISH_POLICIES.join(", ")}"
      end
    end

    attr_reader :dispatch_schema, :source_repo, :version, :tag, :release_id, :source_run_id,
                :target_commitish_policy
  end

  class ReleaseValidator
    def initialize(client:)
      @client = client
    end

    def release_for(inputs)
      release = @client.release_by_tag(inputs.tag)
      validate_release_object!(release, inputs.tag, "release returned by tag")

      release_id = normalized_release_id(release, "release returned by tag")
      if inputs.release_id
        fail Error, "release_id does not match release returned by tag" unless release_id == inputs.release_id

        release_by_id = @client.release_by_id(inputs.release_id)
        validate_release_object!(release_by_id, inputs.tag, "release returned by id")
        unless normalized_release_id(release_by_id, "release returned by id") == inputs.release_id
          fail Error, "release returned by id has an unexpected id"
        end
      end

      release
    end

    def enforce_target_commitish_policy!(release, metadata, policy)
      return if policy == "ignore"

      target_commitish = release["target_commitish"]
      unless target_commitish.is_a?(String) && PMFormulaBump::COMMIT_PATTERN.match?(target_commitish)
        fail Error, "release target_commitish must be a full commit SHA when target_commitish_policy=require-full-sha"
      end
      return if target_commitish == metadata.fetch("commit")

      fail Error, "release target_commitish does not match immutable tag commit"
    end

    private

    def validate_release_object!(release, tag, description)
      fail Error, "#{description} must be a JSON object" unless release.is_a?(Hash)
      fail Error, "#{description} tag_name does not match #{tag}" unless release["tag_name"] == tag
      fail Error, "#{description} draft field must be boolean" unless [true, false].include?(release["draft"])
      fail Error, "#{description} prerelease field must be boolean" unless [true, false].include?(release["prerelease"])
      fail Error, "draft releases are not eligible for dry-run verification" if release["draft"]
      fail Error, "prerelease versions are not eligible for dry-run verification" if release["prerelease"]

      published_at = release["published_at"]
      fail Error, "#{description} must have published_at" unless published_at.is_a?(String) && !published_at.empty?
      Time.iso8601(published_at)
    rescue ArgumentError
      raise Error, "#{description} published_at must be an ISO-8601 timestamp"
    end

    def normalized_release_id(release, description)
      id = release["id"]
      id_string = id.is_a?(Integer) ? id.to_s : id
      PMReleaseVerifier.validate_decimal!(id_string, "#{description} id", required: true)
    end
  end

  class AssetVerifier
    def initialize(client:, external_verifier: ExternalVerifier.new)
      @client = client
      @external_verifier = external_verifier
    end

    def verify!(release:, metadata:, source_run_id:)
      version = metadata.fetch("version")
      tag = metadata.fetch("tag")
      commit = metadata.fetch("commit")
      assets_by_name = validate_asset_inventory!(release.fetch("assets"), version)

      checksum_entries = nil
      subject_digests = nil
      with_verified_asset!(assets_by_name.fetch(CHECKSUMS_NAME), tag) do |path, checksums_digest|
        checksums_bytes = File.binread(path)
        checksum_entries = parse_checksum_manifest!(checksums_bytes, PMReleaseVerifier.expected_subject_asset_names(version))
        subject_digests = { CHECKSUMS_NAME => checksums_digest }.merge(checksum_entries)

        verify_signed_subject!(
          name: CHECKSUMS_NAME,
          subject_path: path,
          digest: checksums_digest,
          assets_by_name: assets_by_name,
          tag: tag,
          commit: commit,
          source_run_id: source_run_id,
          expected_attestation_subjects: subject_digests,
        )
      end

      PMReleaseVerifier.expected_subject_asset_names(version).each do |name|
        with_verified_asset!(assets_by_name.fetch(name), tag) do |path, digest|
          expected_digest = checksum_entries.fetch(name)
          unless digest == expected_digest
            fail Error, "checksum manifest digest for #{name} does not match downloaded asset"
          end

          verify_signed_subject!(
            name: name,
            subject_path: path,
            digest: digest,
            assets_by_name: assets_by_name,
            tag: tag,
            commit: commit,
            source_run_id: source_run_id,
            expected_attestation_subjects: subject_digests,
          )
        end
      end

      {
        "asset_count" => PMReleaseVerifier.expected_release_asset_names(version).length,
        "signed_subject_count" => PMReleaseVerifier.signed_subject_names(version).length,
        "expected_assets" => PMReleaseVerifier.expected_release_asset_names(version),
        "checksummed_assets" => PMReleaseVerifier.expected_subject_asset_names(version),
      }
    end

    private

    def validate_asset_inventory!(assets, version)
      fail Error, "release assets must be an array" unless assets.is_a?(Array)

      expected = PMReleaseVerifier.expected_release_asset_names(version)
      by_name = Hash.new { |hash, key| hash[key] = [] }
      unsafe_names = []
      assets.each do |asset|
        fail Error, "release asset entries must be JSON objects" unless asset.is_a?(Hash)

        name = asset["name"]
        fail Error, "release asset name must be a string" unless name.is_a?(String) && !name.empty?
        unsafe_names << name unless SAFE_ASSET_NAME_PATTERN.match?(name)
        by_name[name] << asset
      end

      names = by_name.keys
      missing = expected - names
      unexpected = names - expected
      duplicates = by_name.select { |_name, values| values.length > 1 }.keys
      not_uploaded = by_name.values.flatten.select { |asset| asset["state"] != "uploaded" }.map { |asset| asset["name"] }.uniq
      problems = []
      problems << "missing: #{missing.join(", ")}" unless missing.empty?
      problems << "unexpected: #{unexpected.join(", ")}" unless unexpected.empty?
      problems << "duplicates: #{duplicates.join(", ")}" unless duplicates.empty?
      problems << "not uploaded: #{not_uploaded.join(", ")}" unless not_uploaded.empty?
      problems << "unsafe names: #{unsafe_names.join(", ")}" unless unsafe_names.empty?
      fail Error, "release asset inventory mismatch (#{problems.join("; ")})" unless problems.empty?

      expected.to_h { |name| [name, by_name.fetch(name).first] }
    end

    def parse_checksum_manifest!(bytes, expected_names)
      text = bytes.encode("UTF-8", invalid: :replace, undef: :replace)
      fail Error, "checksum manifest must not contain replacement characters" if text.include?("\uFFFD")
      fail Error, "checksum manifest must end with a newline" unless text.end_with?("\n")

      entries = {}
      text.lines(chomp: true).each do |line|
        fail Error, "checksum manifest must not contain blank lines" if line.empty?

        match = /\A([0-9a-f]{64})  ([A-Za-z0-9._-]+)\z/.match(line)
        fail Error, "checksum manifest line has unsupported format: #{line.inspect}" unless match

        digest = match[1]
        name = match[2]
        fail Error, "checksum manifest must not bind sigstore bundles" if name.end_with?(COSIGN_BUNDLE_SUFFIX)
        fail Error, "checksum manifest must not contain duplicate entries for #{name}" if entries.key?(name)

        entries[name] = digest
      end

      missing = expected_names - entries.keys
      unexpected = entries.keys - expected_names
      problems = []
      problems << "missing: #{missing.join(", ")}" unless missing.empty?
      problems << "unexpected: #{unexpected.join(", ")}" unless unexpected.empty?
      fail Error, "checksum manifest asset set mismatch (#{problems.join("; ")})" unless problems.empty?

      entries
    end

    def verify_signed_subject!(name:, subject_path:, digest:, assets_by_name:, tag:, commit:, source_run_id:, expected_attestation_subjects:)
      bundle_name = "#{name}#{COSIGN_BUNDLE_SUFFIX}"
      with_verified_asset!(assets_by_name.fetch(bundle_name), tag) do |bundle_path, _bundle_digest|
        CosignBundleVerifier.verify!(
          bundle_path: bundle_path,
          subject_path: subject_path,
          external_verifier: @external_verifier,
          expected_name: name,
          expected_digest: digest,
          tag: tag,
          commit: commit,
          source_run_id: source_run_id,
        )
      end
      AttestationVerifier.new(external_verifier: @external_verifier).verify!(
        subject_path: subject_path,
        expected_name: name,
        expected_digest: digest,
        expected_subjects: expected_attestation_subjects,
        tag: tag,
        commit: commit,
        source_run_id: source_run_id,
      )
    end

    def with_verified_asset!(asset, tag)
      @client.download_release_asset(asset.fetch("name"), tag) do |path|
        digest = Digest::SHA256.file(path).hexdigest
        assert_release_asset_digest!(asset, digest)
        yield path, digest
      end
    end

    def assert_release_asset_digest!(asset, actual_digest)
      digest_field = asset["digest"]
      match = SHA256_DIGEST_PATTERN.match(digest_field.to_s)
      fail Error, "release asset #{asset.fetch("name")} must expose a sha256 digest" unless match
      return if match[1] == actual_digest

      fail Error, "release asset #{asset.fetch("name")} digest does not match downloaded bytes"
    end
  end

  class CosignBundleVerifier
    def self.verify!(bundle_path:, subject_path:, external_verifier:, expected_name:, expected_digest:, tag:, commit:, source_run_id:)
      external_verifier.verify_cosign_blob!(
        subject_path: subject_path,
        bundle_path: bundle_path,
        expected_name: expected_name,
        tag: tag,
        commit: commit,
      )
      bundle = PMReleaseVerifier.parse_json_object(File.binread(bundle_path), "Cosign bundle for #{expected_name}")
      cert = PMReleaseVerifier.certificate_from_sigstore_bundle(bundle, "Cosign certificate for #{expected_name}")
      CertificatePolicy.validate!(cert, tag: tag, commit: commit, source_run_id: source_run_id)
      fail Error, "Cosign subject digest for #{expected_name} is invalid" unless PMFormulaBump::SHA256_PATTERN.match?(expected_digest)
    end
  end

  class CertificatePolicy
    def self.validate!(cert, tag:, commit:, source_run_id:)
      values = extension_utf8_values(cert)
      issuer = required_claim(values, :issuer, "certificate issuer")
      repository = required_claim(values, :repository, "certificate repository")
      workflow_name = required_claim(values, :workflow_name, "certificate workflow name")
      commit_sha = required_claim(values, :commit_sha, "certificate commit")
      ref = required_claim(values, :ref, "certificate ref")

      unless issuer == GITHUB_OIDC_ISSUER
        fail Error, "certificate issuer is not GitHub Actions OIDC"
      end
      unless repository == SOURCE_REPO
        fail Error, "certificate repository does not match #{SOURCE_REPO}"
      end
      unless workflow_name == RELEASE_WORKFLOW_NAME
        fail Error, "certificate workflow name does not match #{RELEASE_WORKFLOW_NAME}"
      end
      unless commit_sha == commit
        fail Error, "certificate commit does not match immutable tag commit"
      end

      allowed_policies = PMReleaseVerifier.certificate_policies(tag)
      unless allowed_policies.any? { |policy| policy.fetch(:ref) == ref }
        fail Error, "certificate ref is not an approved PM release ref"
      end
      unless allowed_policies.any? { |policy| policy.fetch(:ref) == ref && subject_alt_names(cert).include?(policy.fetch(:identity)) }
        fail Error, "certificate subject identity is not the PM release workflow"
      end
      return unless source_run_id

      run_url = required_claim(values, :run_url, "certificate run URL")
      expected_run_url = %r{\Ahttps://github\.com/#{Regexp.escape(SOURCE_REPO)}/actions/runs/#{Regexp.escape(source_run_id)}/attempts/[1-9][0-9]*\z}
      return if expected_run_url.match?(run_url)

      fail Error, "certificate does not bind source_run_id #{source_run_id}"
    end

    def self.subject_alt_names(cert)
      san = cert.extensions.find { |extension| extension.oid == "subjectAltName" }
      return [] unless san

      san.value.split(/,\s*/).filter_map do |entry|
        entry.delete_prefix("URI:") if entry.start_with?("URI:")
      end
    end
    private_class_method :subject_alt_names

    def self.extension_utf8_values(cert)
      cert.extensions.each_with_object(Hash.new { |hash, key| hash[key] = [] }) do |extension, values|
        next unless SIGSTORE_OIDS.value?(extension.oid)

        values[extension.oid] << decode_utf8_extension(extension)
      end
    end
    private_class_method :extension_utf8_values

    def self.decode_utf8_extension(extension)
      extension_sequence = OpenSSL::ASN1.decode(extension.to_der)
      octet = extension_sequence.value.find { |value| value.is_a?(OpenSSL::ASN1::OctetString) }
      fail Error, "certificate extension #{extension.oid} is malformed" unless octet

      decoded = OpenSSL::ASN1.decode(octet.value)
      unless decoded.is_a?(OpenSSL::ASN1::UTF8String)
        fail Error, "certificate extension #{extension.oid} must be a UTF8String"
      end

      decoded.value
    rescue OpenSSL::ASN1::ASN1Error => e
      raise Error, "certificate extension #{extension.oid} could not be decoded: #{e.message}"
    end
    private_class_method :decode_utf8_extension

    def self.required_claim(values, key, description)
      oid = SIGSTORE_OIDS.fetch(key)
      claim_values = values.fetch(oid, [])
      fail Error, "#{description} claim is missing" if claim_values.empty?
      fail Error, "#{description} claim appears multiple times" if claim_values.length > 1

      claim_values.first
    end
    private_class_method :required_claim
  end

  class AttestationVerifier
    def initialize(external_verifier:)
      @external_verifier = external_verifier
    end

    def verify!(subject_path:, expected_name:, expected_digest:, expected_subjects:, tag:, commit:, source_run_id:)
      attestations = @external_verifier.verify_github_attestation!(
        subject_path: subject_path,
        expected_name: expected_name,
        tag: tag,
        commit: commit,
      )
      fail Error, "GitHub artifact attestation verification output for #{expected_name} must be an array" unless attestations.is_a?(Array)
      fail Error, "missing GitHub artifact attestation for #{expected_name}" if attestations.empty?
      fail Error, "ambiguous GitHub artifact attestations for #{expected_name}" if attestations.length > 1

      verify_entry!(attestations.first, expected_name, expected_digest, expected_subjects, tag, commit, source_run_id)
    end

    private

    def verify_entry!(entry, expected_name, expected_digest, expected_subjects, tag, commit, source_run_id)
      fail Error, "GitHub artifact attestation for #{expected_name} must be an object" unless entry.is_a?(Hash)

      bundle = entry.dig("attestation", "bundle")
      fail Error, "GitHub artifact attestation for #{expected_name} is missing bundle" unless bundle.is_a?(Hash)
      unless bundle["mediaType"] == ATTESTATION_BUNDLE_MEDIA_TYPE
        fail Error, "GitHub artifact attestation for #{expected_name} has unsupported mediaType"
      end

      cert = PMReleaseVerifier.certificate_from_sigstore_bundle(
        bundle,
        "GitHub artifact attestation certificate for #{expected_name}",
      )
      CertificatePolicy.validate!(cert, tag: tag, commit: commit, source_run_id: source_run_id)

      statement = entry.dig("verificationResult", "statement")
      fail Error, "GitHub artifact attestation statement for #{expected_name} must be an object" unless statement.is_a?(Hash)

      validate_statement!(statement, expected_name, expected_digest, expected_subjects)
    end

    def validate_statement!(statement, expected_name, expected_digest, expected_subjects)
      fail Error, "GitHub artifact attestation statement has unsupported _type" unless statement["_type"] == IN_TOTO_STATEMENT_TYPE
      fail Error, "GitHub artifact attestation statement has unsupported predicateType" unless statement["predicateType"] == SLSA_PROVENANCE_TYPE

      subject_map = statement_subject_map(statement["subject"])
      unless subject_map[expected_name] == expected_digest
        fail Error, "GitHub artifact attestation statement does not bind #{expected_name}"
      end
      return if subject_map == expected_subjects

      fail Error, "GitHub artifact attestation statement subject set does not match expected PM assets"
    end

    def statement_subject_map(subjects)
      fail Error, "GitHub artifact attestation statement subject must be an array" unless subjects.is_a?(Array)

      subjects.each_with_object({}) do |subject, result|
        fail Error, "GitHub artifact attestation subject entries must be objects" unless subject.is_a?(Hash)

        name = subject["name"]
        digest = subject.dig("digest", "sha256")
        unless name.is_a?(String) && SAFE_ASSET_NAME_PATTERN.match?(name) && PMFormulaBump::SHA256_PATTERN.match?(digest.to_s)
          fail Error, "GitHub artifact attestation subject has unsupported name or digest"
        end
        fail Error, "GitHub artifact attestation subject contains duplicate #{name}" if result.key?(name)

        result[name] = digest
      end
    end
  end

  class Operations
    SUMMARY_KEYS = %w[
      schema
      dispatch_schema
      source_repo
      version
      tag
      release_id
      target_commitish_policy
      source_run_id
      formula_dry_run
      metadata
      release_assets
    ].freeze

    def initialize(root: PMFormulaBump.default_root, client: GitHubClient.new, external_verifier: ExternalVerifier.new)
      @root = File.realpath(root)
      @client = client
      @planner = PMFormulaBump::Planner.new(client: @client)
      @paths = PMFormulaBump::Paths.new(root: @root)
      @formula_operations = PMFormulaBump::Operations.new(root: @root, planner: @planner)
      @release_validator = ReleaseValidator.new(client: @client)
      @asset_verifier = AssetVerifier.new(client: @client, external_verifier: external_verifier)
    end

    def verify(dispatch_schema:, source_repo:, version:, release_id:, source_run_id:, target_commitish_policy:,
               metadata_out:, verification_out:, formula_path:, readme_path:)
      inputs = Inputs.new(
        dispatch_schema: dispatch_schema,
        source_repo: source_repo,
        version: version,
        release_id: release_id,
        source_run_id: source_run_id,
        target_commitish_policy: target_commitish_policy,
      )
      metadata_path = output_path(metadata_out, "metadata-out")
      verification_path = output_path(verification_out, "verification-out")

      release = @release_validator.release_for(inputs)
      metadata = @planner.plan(inputs.tag)
      @release_validator.enforce_target_commitish_policy!(release, metadata, inputs.target_commitish_policy)
      release_assets = @asset_verifier.verify!(
        release: release,
        metadata: metadata,
        source_run_id: inputs.source_run_id,
      )

      write_file(metadata_path, PMFormulaBump.stable_json(metadata))
      formula_dry_run = @formula_operations.apply(
        metadata_path: metadata_path,
        formula_path: formula_path,
        readme_path: readme_path,
        write: false,
      )

      summary = stable_summary(
        "schema" => VERIFICATION_SCHEMA,
        "dispatch_schema" => inputs.dispatch_schema,
        "source_repo" => inputs.source_repo,
        "version" => inputs.version,
        "tag" => inputs.tag,
        "release_id" => normalized_release_id(release),
        "target_commitish_policy" => inputs.target_commitish_policy,
        "source_run_id" => inputs.source_run_id,
        "formula_dry_run" => formula_dry_run.chomp,
        "metadata" => metadata,
        "release_assets" => release_assets,
      )
      write_file(verification_path, "#{JSON.pretty_generate(summary)}\n")
      summary
    end

    private

    def output_path(path, description)
      resolved = @paths.metadata_path(path, description)
      @paths.ensure_metadata_parent!(resolved)
      resolved
    end

    def write_file(path, content)
      dir = File.dirname(path)
      Tempfile.create(["pm-release-verifier-", ".json"], dir) do |tmp|
        tmp.write(content)
        tmp.flush
        tmp.fsync
        FileUtils.mv(tmp.path, path)
      end
    end

    def normalized_release_id(release)
      id = release.fetch("id")
      id.is_a?(Integer) ? id.to_s : id
    end

    def stable_summary(hash)
      SUMMARY_KEYS.to_h { |key| [key, hash.fetch(key)] }
    end
  end

  class CLI
    def initialize(argv, operations: Operations.new)
      @argv = argv.dup
      @operations = operations
    end

    def run
      command = @argv.shift
      fail Error, "command must be verify" unless command == "verify"

      options = parse_verify_options
      summary = @operations.verify(**options)
      $stdout.write("#{JSON.pretty_generate(summary)}\n")
      0
    rescue Error, PMFormulaBump::Error, OptionParser::ParseError, KeyError => e
      $stderr.puts("pm_release_verifier: #{e.message}")
      1
    end

    private

    def parse_verify_options
      options = {
        release_id: "",
        source_run_id: "",
        target_commitish_policy: "ignore",
      }
      parser = OptionParser.new do |opts|
        opts.banner = <<~BANNER.chomp
          Usage: #{$PROGRAM_NAME} verify --dispatch-schema #{DISPATCH_SCHEMA} --source-repo #{SOURCE_REPO} --version X.Y.Z --metadata-out <path> --verification-out <path> --formula Formula/pm.rb --readme README.md
        BANNER
        opts.on("--dispatch-schema SCHEMA") { |value| options[:dispatch_schema] = value }
        opts.on("--source-repo REPO") { |value| options[:source_repo] = value }
        opts.on("--version VERSION") { |value| options[:version] = value }
        opts.on("--release-id ID") { |value| options[:release_id] = value }
        opts.on("--source-run-id ID") { |value| options[:source_run_id] = value }
        opts.on("--target-commitish-policy POLICY") { |value| options[:target_commitish_policy] = value }
        opts.on("--metadata-out PATH") { |value| options[:metadata_out] = value }
        opts.on("--verification-out PATH") { |value| options[:verification_out] = value }
        opts.on("--formula PATH") { |value| options[:formula_path] = value }
        opts.on("--readme PATH") { |value| options[:readme_path] = value }
      end
      parser.parse!(@argv)
      fail Error, "unexpected positional arguments: #{@argv.join(" ")}" unless @argv.empty?

      %i[dispatch_schema source_repo version metadata_out verification_out formula_path readme_path].each do |key|
        fail Error, "--#{key.to_s.tr("_", "-")} is required" unless options[key]
      end
      options
    end
  end
end

if $PROGRAM_NAME == __FILE__
  exit PMReleaseVerifier::CLI.new(ARGV).run
end
