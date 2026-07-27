class Pm < Formula
  desc "Polymetrics command-line interface"
  homepage "https://github.com/polymetrics-ai/cli"
  url "https://github.com/polymetrics-ai/cli/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "c947c513a2e192b5b730070ef2052e14eadacd199edc4d3051943a65c27050ea"
  license all_of: ["AGPL-3.0-only", "MIT"]

  depends_on "go" => :build

  def install
    ENV["CGO_ENABLED"] = "0"
    ENV["GOTOOLCHAIN"] = "local"

    ldflags = %w[
      -X polymetrics.ai/internal/cli.version=0.1.0
      -X polymetrics.ai/internal/cli.commit=6de947ca89946a461b5c4c5b0daadf3a0f0f6ad6
      -X polymetrics.ai/internal/cli.buildDate=2026-07-27T16:59:34+05:30
    ]

    system "go", "build", *std_go_args(ldflags:, output: bin/"pm"), "./cmd/pm"

    pkgshare.install "LICENSE", "NOTICE", "LICENSING.md"
    (pkgshare/"licenses/connector-definitions").install "internal/connectors/defs/LICENSE"
  end

  test do
    version_output = shell_output("#{bin}/pm version --json")
    version_json = JSON.parse(version_output)
    assert_equal "polymetrics.ai/v1", version_json["api_version"]
    assert_equal "Version", version_json["kind"]
    assert_equal "0.1.0", version_json["version"]
    assert_equal "6de947ca89946a461b5c4c5b0daadf3a0f0f6ad6", version_json["commit"]

    connector_output = shell_output("#{bin}/pm connectors inspect sample --json")
    connector_json = JSON.parse(connector_output)
    assert_equal "polymetrics.ai/v1", connector_json["api_version"]
    assert_equal "sample", connector_json.dig("connector", "name")

    assert_path_exists pkgshare/"LICENSING.md"
    assert_path_exists pkgshare/"licenses/connector-definitions/LICENSE"
  end
end
