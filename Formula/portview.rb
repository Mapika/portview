class Portview < Formula
  desc "See what's on your ports, then act on it"
  homepage "https://github.com/mapika/portview"
  version "0.4.0"
  license "MIT"

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-linux-x86_64.tar.gz"
      sha256 "c58da009b96f744e5d6611a8260f5be2953a41998876d184e31c541bb875d528"
    elsif Hardware::CPU.arm?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-linux-aarch64.tar.gz"
      sha256 "46e5d1141086f18437217bb883881af0a79f419e4163a313f500a144976842c5"
    end
  end

  def install
    bin.install "portview"
  end

  test do
    assert_match "portview", shell_output("#{bin}/portview --version")
  end
end
