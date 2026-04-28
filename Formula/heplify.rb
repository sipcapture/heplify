# frozen_string_literal: true

# Homebrew tap served from this repo:
#   brew tap sipcapture/heplify https://github.com/sipcapture/heplify
#   brew install heplify
#
# Bump on each release (GitHub tag matches version, e.g. 2.0.17):
#   shasum -a 256 "$(curl -sL "https://github.com/sipcapture/heplify/releases/download/<TAG>/heplify_darwin_arm64")"
# Prebuilt macOS binary is arm64 (Apple Silicon) only — same as CI.
class Heplify < Formula
  desc "HEP capture agent for Homer / SIP capture (SIP, RTCP, logs, HEP forward)"
  homepage "https://github.com/sipcapture/heplify"
  version "2.0.17"
  license "AGPL-3.0-or-later"

  on_macos do
    on_arm do
      url "https://github.com/sipcapture/heplify/releases/download/#{version}/heplify_darwin_arm64"
      # Update sha256 after CI uploads the 2.0.17 release asset (see header comment).
      sha256 "05cd9e8fafc84b3438ff6fa903f783a25bf7538f2332577136895a93c9f24157"
    end
  end

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
