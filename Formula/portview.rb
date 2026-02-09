class Portview < Formula
  desc "See what's on your ports, then act on it"
  homepage "https://github.com/mapika/portview"
  version "1.0.0"
  license "MIT"

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-linux-x86_64.tar.gz"
      sha256 "3ed66d88fec685bdc4e3d52197272e91790fa12b701e70bb8ea574382561f6ef"
    elsif Hardware::CPU.arm?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-linux-aarch64.tar.gz"
      sha256 "a3b250fc4adca31d9124eed7c0c58f4390b9996c44d52af75508ee5bc8295835"
    end
  end

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-darwin-x86_64.tar.gz"
      sha256 "0b3ce450179174c5ec5888f7de695c42e8845a99589fd0cfcb2e74f3d50e56f6"
    elsif Hardware::CPU.arm?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-darwin-aarch64.tar.gz"
      sha256 "149031118a01ca2cbbb7d52ff24c98d132e0a2cd26678240c454d4121b494f1f"
    end
  end

  def install
    bin.install "portview"
  end

  test do
    assert_match "portview", shell_output("#{bin}/portview --version")
  end
end
