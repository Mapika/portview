class Portview < Formula
  desc "See what's on your ports, then act on it"
  homepage "https://github.com/mapika/portview"
  version "0.6.0"
  license "MIT"

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-linux-x86_64.tar.gz"
      sha256 "c136d661497433c299ee4830249e86aa66c4a2e569bbd33fcd3e595690afe0e4"
    elsif Hardware::CPU.arm?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-linux-aarch64.tar.gz"
      sha256 "75a2e08e71e9c24e3222e72c02dd4a246b582bb3c40d2d3e116e72d101eb70bd"
    end
  end

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-darwin-x86_64.tar.gz"
      sha256 "2079a915ee5606b5ec98bc5924e371106383521327b0af3f6c12a42bf710d4d8"
    elsif Hardware::CPU.arm?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-darwin-aarch64.tar.gz"
      sha256 "8e8d20342d71072e382d91692090d6d1c650d5e002fdce24795435010d902b9a"
    end
  end

  def install
    bin.install "portview"
  end

  test do
    assert_match "portview", shell_output("#{bin}/portview --version")
  end
end
