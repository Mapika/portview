class Portview < Formula
  desc "See what's on your ports, then act on it"
  homepage "https://github.com/mapika/portview"
  version "0.6.0"
  license "MIT"

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-linux-x86_64.tar.gz"
      sha256 "e56c62095de0899a47bd6dfc659a2f09df315a2d38561bffabea84737ab64ff2"
    elsif Hardware::CPU.arm?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-linux-aarch64.tar.gz"
      sha256 "31bccb548d3aa8eb4ef502ab1a3ec70f0e2e43b90107a1f72a68cd7425840824"
    end
  end

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-darwin-x86_64.tar.gz"
      sha256 "3d22853c28f359f44cb7bbeb9230a0f48265350e82812254effa4161a033a755"
    elsif Hardware::CPU.arm?
      url "https://github.com/mapika/portview/releases/download/v#{version}/portview-darwin-aarch64.tar.gz"
      sha256 "fa02d752cf8f88aa809f0ca7854e4a03e525a3a10b300817a9e0eaabf1607b5c"
    end
  end

  def install
    bin.install "portview"
  end

  test do
    assert_match "portview", shell_output("#{bin}/portview --version")
  end
end
