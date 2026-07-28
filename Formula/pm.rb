class Pm < Formula
  desc "Polymetrics command-line interface"
  homepage "https://github.com/polymetrics-ai/cli"
  url "https://github.com/polymetrics-ai/cli/archive/refs/tags/v0.1.1.tar.gz"
  sha256 "09e94f2a6524d881aed328c30b27f9ff39e40975fea67b4a540ea76a8ef4fa00"
  license all_of: ["AGPL-3.0-only", "MIT"]

  depends_on "go" => :build

  def install
    ENV["CGO_ENABLED"] = "0"
    ENV["GOTOOLCHAIN"] = "local"

    ldflags = %w[
      -X polymetrics.ai/internal/cli.version=0.1.1
      -X polymetrics.ai/internal/cli.commit=4a30b802d5b9ab7188181eacac1812cceed0e543
      -X polymetrics.ai/internal/cli.buildDate=2026-07-28T12:29:42Z
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
    assert_equal "0.1.1", version_json["version"]
    assert_equal "4a30b802d5b9ab7188181eacac1812cceed0e543", version_json["commit"]
    assert_equal "2026-07-28T12:29:42Z", version_json["date"]

    connector_output = shell_output("#{bin}/pm connectors inspect sample --json")
    connector_json = JSON.parse(connector_output)
    assert_equal "polymetrics.ai/v1", connector_json["api_version"]
    assert_equal "sample", connector_json.dig("connector", "name")

    assert_path_exists pkgshare/"LICENSING.md"
    assert_path_exists pkgshare/"licenses/connector-definitions/LICENSE"
  end
end
