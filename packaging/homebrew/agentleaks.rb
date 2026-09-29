# Homebrew formula for a tap, filled in from the v0.1.0 release checksums.
class Agentleaks < Formula
  desc "Find, redact and block API keys in AI coding tool history"
  homepage "https://github.com/Arthur031221/agentleaks"
  license "MIT"
  version "0.1.0"

  base = "https://github.com/Arthur031221/agentleaks/releases/download/v#{version}"

  on_macos do
    if Hardware::CPU.arm?
      url "#{base}/agentleaks_#{version}_darwin_arm64.tar.gz"
      sha256 "c9526f7f61d96a77ac977b95c4bd50e799f59a6ff1e80ad63f2cc7e1adb36b29"
    else
      url "#{base}/agentleaks_#{version}_darwin_amd64.tar.gz"
      sha256 "51959aa51b00ae527867c3bb3ac7825e2422c317d287605703c23ebd408abb51"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "#{base}/agentleaks_#{version}_linux_arm64.tar.gz"
      sha256 "3c5c534868c281b12ea38319a28f8de6868e8323cdac7d615d23813a98a1ac29"
    else
      url "#{base}/agentleaks_#{version}_linux_amd64.tar.gz"
      sha256 "32f0e5ac0f1058e2124c74f86a9b48e5ba0b7561184d29d0d6a7afd6b4dc8800"
    end
  end

  def install
    bin.install "agentleaks"
  end

  test do
    assert_match "agentleaks", shell_output("#{bin}/agentleaks version")
  end
end
