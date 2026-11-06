# frozen_string_literal: true

# Homebrew tap served from this repo:
#   brew tap sipcapture/heplify https://github.com/sipcapture/heplify
#   brew install heplify
#
# Bump on each release (GitHub tag matches version, e.g. 2.0.28):
#   scripts/update_formula.sh <VERSION>
# Prebuilt macOS binary is arm64 (Apple Silicon) only — same as CI.
class Heplify < Formula
  desc "HEP capture agent for Homer / SIP capture (SIP, RTCP, logs, HEP forward)"
  homepage "https://github.com/sipcapture/heplify"
  url "https://github.com/sipcapture/heplify/releases/download/2.0.28/heplify_darwin_arm64"
  sha256 "6c1cf3039112ecb146b7f1696dcd9f4cd8912ed46a2d571ceea714c790e28b4b"
  license "AGPL-3.0-or-later"

  livecheck do
    url :homepage
    strategy :github_latest
  end

  depends_on arch: :arm64
  depends_on :macos

  def install
    bin.install "heplify_darwin_arm64" => "heplify"
  end

  def caveats
    <<~EOS
      Live capture on macOS usually requires root or appropriate permissions, e.g.:
        sudo heplify -config /path/to/heplify.json
    EOS
  end

  test do
    assert_match "heplify v#{version}", shell_output("#{bin}/heplify -version")
  end
end
