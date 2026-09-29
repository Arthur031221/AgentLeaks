# Homebrew formula template for a tap. Fill the sha256 values from
# checksums.txt on the GitHub release before publishing.
class Agentleaks < Formula
  desc "Find, redact and block API keys in AI coding tool history"
  homepage "https://github.com/Arthur031221/agentleaks"
  license "MIT"
  version "0.1.0"

  base = "https://github.com/Arthur031221/agentleaks/releases/download/v#{version}"

  on_macos do
    if Hardware::CPU.arm?
      url "#{base}/agentleaks_#{version}_darwin_arm64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_FROM_checksums.txt"
    else
      url "#{base}/agentleaks_#{version}_darwin_amd64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_FROM_checksums.txt"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "#{base}/agentleaks_#{version}_linux_arm64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_FROM_checksums.txt"
    else
      url "#{base}/agentleaks_#{version}_linux_amd64.tar.gz"
      sha256 "REPLACE_WITH_SHA256_FROM_checksums.txt"
    end
  end

  def install
    bin.install "agentleaks"
  end

  test do
    assert_match "agentleaks", shell_output("#{bin}/agentleaks version")
  end
end
