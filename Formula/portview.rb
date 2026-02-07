class Portview < Formula
  desc "See what's on your ports, then act on it"
  homepage "https://github.com/mapika/portview"
  version "0.2.0"
  license "MIT"

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-linux-x86_64.tar.gz"
      sha256 "0612583386730c59965fecbc33f6b26db7c8010aa6e6019fe9bb58a50bb21bea"
    elsif Hardware::CPU.arm?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-linux-aarch64.tar.gz"
      sha256 "503cec9c03d6449e07b45cb5dfd67f4ca394c9bf0b57a5016172c69bff914059"
    end
  end

  def install
    bin.install "portview"
  end

  test do
    assert_match "portview", shell_output("#{bin}/portview --version")
  end
end
