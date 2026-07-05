  ── Install ──────────────────────────────────────────────────────────────
    sudo installer -pkg '/Users/rutikmangale/Downloads/macbook_data/agent/os/macos/pkg/dist/attacklens-agent-2.0.1-arm64.pkg' -target /

  ── What happens on install ──────────────────────────────────────────────
    • Binaries installed to /Library/AttackLens/bin/
    • Agent ID auto-derived from hardware UUID (stable across reinstalls)
    • Config written to '/Library/AttackLens/agent.toml'
    • LaunchDaemons loaded: com.attacklens.agent + com.attacklens.watchdog
    • Agent enrolls with manager on first run (open enrollment — no token needed)
    • API key stored in macOS Keychain (com.attacklens.agent)

  No manager URL baked in — edit agent.toml after install:
    sudo nano '/Library/AttackLens/agent.toml'
    Set [manager] url = "https://YOUR_MANAGER_IP:8443"
    Then: sudo launchctl kickstart -k system/com.attacklens.agent

  ── MDM silent deploy (Jamf / Mosyle / Intune) ───────────────────────────
    Upload '/Users/rutikmangale/Downloads/macbook_data/agent/os/macos/pkg/dist/attacklens-agent-2.0.1-arm64.pkg' — no extra scripts needed.


    