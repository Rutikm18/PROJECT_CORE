"""
agent/os/macos/collectors/posture.py — Security posture collectors (1 hr interval).

  security — SIP, Gatekeeper, FileVault, Firewall, XProtect, Secure Boot,
              auto-update, Developer Tools security status
  sysctl   — Security-relevant kernel parameters
  configs  — Shell rc, SSH config, authorized_keys, /etc/hosts (4 KiB cap)

ARM64 additions:
  - Secure Boot level via system_profiler SPiBridgeDataType (T2/M-series)
  - Notarisation status for key system binaries
  - Lockdown Mode detection (launchd env)
"""
from __future__ import annotations

import os
import re

from .base import BaseCollector, CollectorResult, _run, _sp_json


class SecurityCollector(BaseCollector):
    name = "security"

    def collect(self) -> dict:
        return {
            # ── macOS core security controls ──────────────────────────────
            "sip":                   self._sip(),
            "gatekeeper":            self._gatekeeper(),
            "filevault":             self._filevault(),
            "firewall":              self._firewall(),
            "xprotect_version":      self._xprotect(),
            "secure_boot":           self._secure_boot(),
            "auto_update":           self._auto_update(),
            "dev_tools":             self._dev_tools(),
            "lockdown_mode":         self._lockdown_mode(),
            # ── SSH / remote access ───────────────────────────────────────
            "remote_login":          self._remote_login(),          # SSH enabled?
            "remote_management":     self._remote_management(),     # ARD enabled?
            "screen_sharing":        self._screen_sharing(),        # VNC enabled?
            "ssh_password_auth":     self._ssh_password_auth(),
            "ssh_permit_root_login": self._ssh_permit_root_login(),
            # ── Screensaver / session lock ────────────────────────────────
            "screensaver_lock":      self._screensaver_lock(),      # require pw on wake?
            "screensaver_idle_sec":  self._screensaver_idle_sec(),
            # ── AV / EDR ─────────────────────────────────────────────────
            "av_installed":          None,
            "av_product":            None,
            "os_patched":            None,
            # ── Windows/Linux (always None on macOS) ─────────────────────
            "uac": None, "bitlocker": None, "defender": None,
            "selinux": None, "apparmor": None, "ufw": None,
        }

    def _remote_login(self) -> bool | None:
        out = _run(["systemsetup", "-getremotelogin"])
        if "on" in out.lower():
            return True
        if "off" in out.lower():
            return False
        return None

    def _remote_management(self) -> bool | None:
        out = _run(["systemsetup", "-getremoteappleevents"])
        if "on" in out.lower():
            return True
        if "off" in out.lower():
            return False
        return None

    def _screen_sharing(self) -> bool | None:
        out = _run(["launchctl", "list", "com.apple.screensharing"])
        return "0" in out or "running" in out.lower() or None

    def _ssh_password_auth(self) -> str | None:
        sshd = "/etc/ssh/sshd_config"
        try:
            with open(sshd) as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    if stripped.lower().startswith("passwordauthentication"):
                        return stripped.split()[-1].lower()
        except OSError:
            pass
        return None

    def _ssh_permit_root_login(self) -> str | None:
        sshd = "/etc/ssh/sshd_config"
        try:
            with open(sshd) as f:
                for line in f:
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    if stripped.lower().startswith("permitrootlogin"):
                        return stripped.split()[-1].lower()
        except OSError:
            pass
        return None

    def _screensaver_lock(self) -> bool | None:
        out = _run([
            "defaults", "read",
            "com.apple.screensaver", "askForPassword",
        ])
        val = out.strip()
        if val == "1":
            return True
        if val == "0":
            return False
        return None

    def _screensaver_idle_sec(self) -> int | None:
        out = _run(["defaults", "-currentHost", "read",
                    "com.apple.screensaver", "idleTime"])
        try:
            return int(out.strip())
        except (ValueError, TypeError):
            pass
        return None

    def _sip(self) -> str | None:
        out = _run(["csrutil", "status"])
        if "enabled" in out.lower():
            return "enabled"
        if "disabled" in out.lower():
            return "disabled"
        return out.strip() or None

    def _gatekeeper(self) -> str | None:
        out = _run(["spctl", "--status"])
        if "enabled" in out.lower():
            return "enabled"
        if "disabled" in out.lower():
            return "disabled"
        return out.strip() or None

    def _filevault(self) -> str | None:
        out = _run(["fdesetup", "status"])
        if "on" in out.lower():
            return "on"
        if "off" in out.lower():
            return "off"
        return out.strip() or None

    def _firewall(self) -> str | None:
        out = _run([
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            "--getglobalstate",
        ])
        if "enabled" in out.lower():
            return "on"
        if "disabled" in out.lower():
            return "off"
        return out.strip() or None

    def _xprotect(self) -> str | None:
        out = _run([
            "defaults", "read",
            "/Library/Apple/System/Library/CoreServices/XProtect.bundle"
            "/Contents/Info.plist",
            "CFBundleShortVersionString",
        ])
        return out.strip() or None

    def _secure_boot(self) -> str | None:
        sp = _sp_json("SPiBridgeDataType", timeout=15)
        if sp:
            for item in sp.get("SPiBridgeDataType", []):
                boot = item.get("ibridge_secure_boot_level") or \
                       item.get("secure_boot_level")
                if boot:
                    return str(boot)
        # Fallback: nvram
        out = _run(["nvram", "94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy"])
        if out:
            if "0x02" in out:
                return "full"
            if "0x01" in out:
                return "medium"
            if "0x00" in out:
                return "off"
        return None

    def _auto_update(self) -> bool | None:
        out = _run([
            "defaults", "read",
            "/Library/Preferences/com.apple.SoftwareUpdate",
            "AutomaticCheckEnabled",
        ])
        val = out.strip()
        if val == "1":
            return True
        if val == "0":
            return False
        return None

    def _dev_tools(self) -> str | None:
        out = _run(["DevToolsSecurity", "-status"])
        return out.strip() or None

    def _lockdown_mode(self) -> bool | None:
        # Lockdown Mode (macOS 13+): launchctl environment key
        out = _run(["launchctl", "getenv", "com.apple.security.lockdown"])
        return True if "1" in out else (False if out else None)


class SysctlCollector(BaseCollector):
    name = "sysctl"

    _SECURITY_PREFIXES = (
        "kern.hostname",
        "kern.osversion",
        "kern.bootargs",
        "kern.codesign",
        "kern.secure_kernel",
        "kern.hv_vmm_present",
        "net.inet",
        "hw.model",
        "hw.memsize",
        "hw.targettype",
        "vm.loadavg",
        "security.",
        "machdep.cpu.brand_string",
        "machdep.cpu.features",
    )

    def collect(self) -> list:
        rows: list[dict] = []
        for line in _run(["sysctl", "-a"]).splitlines():
            if not any(line.startswith(p) for p in self._SECURITY_PREFIXES):
                continue
            if "=" not in line and ":" not in line:
                continue
            sep = "=" if "=" in line else ":"
            k, _, v = line.partition(sep)
            rows.append({
                "key":              k.strip(),
                "value":            v.strip(),
                "security_relevant": True,
            })
        return rows


class ConfigsCollector(BaseCollector):
    name = "configs"

    _READ_LIMIT = 4096   # 4 KiB cap per file — no accidental secret dumps

    # Download-cradle patterns heuristic (detects suspicious shell configs)
    _SUSPICIOUS_RE = re.compile(
        r"(curl\s+.*\|\s*(?:ba)?sh"
        r"|wget\s+.*\|\s*(?:ba)?sh"
        r"|eval\s+.*base64"
        r"|python.*-c.*exec"
        r"|osascript\s+-e)",
        re.IGNORECASE,
    )

    @property
    def _config_paths(self) -> list[str]:
        home = os.path.expanduser("~")
        return [
            f"{home}/.zshrc",
            f"{home}/.zprofile",
            f"{home}/.bashrc",
            f"{home}/.bash_profile",
            f"{home}/.profile",
            f"{home}/.ssh/config",
            f"{home}/.ssh/authorized_keys",
            "/etc/hosts",
            "/etc/zshrc",
            "/etc/bashrc",
            "/etc/ssh/sshd_config",
            "/etc/pam.d/sudo",
            "/private/etc/sudoers",
        ]

    def collect(self) -> list:
        rows: list[dict] = []
        for path in self._config_paths:
            try:
                with open(path) as f:
                    content = f.read(self._READ_LIMIT)
                rows.append({
                    "path":       path,
                    "content":    content,
                    "suspicious": bool(self._SUSPICIOUS_RE.search(content)),
                })
            except OSError:
                pass
        return rows
