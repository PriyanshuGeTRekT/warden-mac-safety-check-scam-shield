cask "warden" do
  version "1.0.0"
  sha256 "da65d94233262d9b9b51c117edd9028539f2705cfba8d6e46378fc0139e0801f"

  url "https://github.com/PriyanshuGeTRekT/warden-mac-safety-check-scam-shield/releases/download/v#{version}/Warden-#{version}.zip"
  name "Warden"
  desc "Mac Safety Check and shield against remote-access tech-support scams"
  homepage "https://priyanshugetrekt.github.io/warden-mac-safety-check-scam-shield/"

  livecheck do
    url :url
    strategy :github_latest
  end

  depends_on arch: :arm64
  depends_on macos: ">= :sonoma"

  app "Warden.app"
  binary "#{appdir}/Warden.app/Contents/Resources/bin/warden"

  zap trash: [
    "~/Library/Application Support/Warden",
    "~/Library/Preferences/app.warden.mac.plist",
  ]

  caveats <<~EOS
    Warden is not notarized by Apple, so macOS blocks it the first time it opens.
    To allow it, open Warden once, then go to
      System Settings › Privacy & Security
    scroll down and click "Open Anyway" next to Warden.

    To include which apps may record the screen or control the Mac in the Safety
    Check, allow Warden in System Settings › Privacy & Security › Full Disk Access.
    Everything else works without any permission.
  EOS
end
