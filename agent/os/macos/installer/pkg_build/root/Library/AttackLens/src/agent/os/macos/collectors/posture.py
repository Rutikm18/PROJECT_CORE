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
        # Field-resilient: each probe runs in isolation so one failing check
        # (e.g. a root-only command returning unexpected output → a parse error)
        # can NEVER take the whole Security section down. Every field that can
        # be collected always comes through; a field whose probe fails is None.
        probes = {
            # ── macOS core security controls ──────────────────────────────
            "sip":                     self._sip,
            "gatekeeper":              self._gatekeeper,
            "filevault":               self._filevault,
            "firewall":                self._firewall,
            "xprotect_version":        self._xprotect,
            "secure_boot":             self._secure_boot,
            "auto_update":             self._auto_update,
            "dev_tools":               self._dev_tools,
            "lockdown_mode":           self._lockdown_mode,
            # ── SSH / remote access ───────────────────────────────────────
            "remote_login":            self._remote_login,
            "remote_management":       self._remote_management,
            "screen_sharing":          self._screen_sharing,
            "ssh_password_auth":       self._ssh_password_auth,
            "ssh_permit_root_login":   self._ssh_permit_root_login,
            # ── Screensaver / session lock ────────────────────────────────
            "screensaver_lock":        self._screensaver_lock,
            "screensaver_idle_sec":    self._screensaver_idle_sec,
            # ── CIS expansion ─────────────────────────────────────────────
            "audit_enabled":           self._audit_enabled,
            "audit_flags":             self._audit_flags,
            "pw_policy_configured":    self._pw_policy_configured,
            "pw_min_length":           self._pw_min_length,
            "guest_account":           self._guest_account,
            "auto_login_user":         self._auto_login_user,
            "auto_update_install":     self._auto_update_install,
            "critical_update_install": self._critical_update_install,
            "network_time":            self._network_time,
            "time_server":             self._time_server,
            "file_sharing":            self._file_sharing,
            "printer_sharing":         self._printer_sharing,
        }
        result: dict = {}
        for field, fn in probes.items():
            try:
                result[field] = fn()
            except Exception:
                result[field] = None   # never let one probe sink the section
        # Static / cross-platform fields
        result.update({
            "av_installed": None, "av_product": None, "os_patched": None,
            "uac": None, "bitlocker": None, "defender": None,
            "selinux": None, "apparmor": None, "ufw": None,
        })
        # Privilege hint so the dashboard can distinguish "secure" from
        # "couldn't read (needs root)" — root-only probes return None unprivileged.
        result["_collected_as_root"] = (os.geteuid() == 0) if hasattr(os, "geteuid") else None
        return result

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
        # Was `"0" in out` — which matched the `"LastExitStatus" = 0;` line
        # present in almost every loaded service's plist, reporting Screen
        # Sharing as ON even when it was off. Use the same load-state probe the
        # other sharing checks use (presence of the label == service loaded).
        return self._svc_loaded("com.apple.screensharing")

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

    # ── CIS expansion helpers ─────────────────────────────────────────────────

    def _svc_loaded(self, label: str) -> bool | None:
        """Whether a launchd system service is loaded.

        `launchctl list <label>` echoes a plist containing the label when the
        service is loaded, and writes 'Could not find service' to stderr when it
        is not.  Returns None only when neither signal is present (can't tell) —
        never guesses 'disabled', so we don't mask an enabled sharing service.
        """
        out = _run(["launchctl", "list", label])
        if label in out:
            return True
        err = _run(["launchctl", "list", label], stderr=True)
        if "could not find" in err.lower() or "no such" in err.lower():
            return False
        return None

    def _defaults_bool(self, domain: str, key: str) -> bool | None:
        out = _run(["defaults", "read", domain, key]).strip()
        if out == "1":
            return True
        if out == "0":
            return False
        return None

    def _audit_enabled(self) -> bool | None:
        """BSM audit subsystem (auditd) active?  CIS logging control."""
        loaded = self._svc_loaded("com.apple.auditd")
        if loaded:
            return True
        # Fallback: presence of a configured audit_control with active flags.
        try:
            with open("/etc/security/audit_control") as f:
                for line in f:
                    if line.strip().startswith("flags:") and line.split(":", 1)[1].strip():
                        return True
        except OSError:
            return loaded   # None or False from the service probe
        return loaded

    def _audit_flags(self) -> str | None:
        try:
            with open("/etc/security/audit_control") as f:
                for line in f:
                    if line.strip().startswith("flags:"):
                        return line.split(":", 1)[1].strip() or None
        except OSError:
            pass
        return None

    def _pw_policy_configured(self) -> bool | None:
        """Whether a global password-content policy is set (length/age/lockout)."""
        out = _run(["pwpolicy", "-getaccountpolicies"])
        if not out:
            return None
        low = out.lower()
        if "no accountpolicies" in low:
            return False
        if "policycontent" in low or "policyattribute" in low or "minimumlength" in low:
            return True
        return False

    def _pw_min_length(self) -> int | None:
        out = _run(["pwpolicy", "-getaccountpolicies"])
        if not out:
            return None
        # Global policy expresses minimum length as `minimumLength` (plist int)
        # or inside a content regex like `.{N,}` / `{N,}`.
        m = re.search(r"minimumLength\D{0,40}?(\d+)", out, re.IGNORECASE | re.DOTALL)
        if not m:
            m = re.search(r"\{(\d+),\}", out)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                pass
        return None

    def _guest_account(self) -> bool | None:
        return self._defaults_bool(
            "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"
        )

    def _auto_login_user(self) -> str | None:
        """Configured automatic-login user, or '' when auto-login is off."""
        out = _run(["defaults", "read",
                    "/Library/Preferences/com.apple.loginwindow",
                    "autoLoginUser"]).strip()
        if not out or "does not exist" in out.lower():
            return ""          # explicitly: no auto-login configured (good)
        return out

    def _auto_update_install(self) -> bool | None:
        return self._defaults_bool(
            "/Library/Preferences/com.apple.SoftwareUpdate",
            "AutomaticallyInstallMacOSUpdates",
        )

    def _critical_update_install(self) -> bool | None:
        return self._defaults_bool(
            "/Library/Preferences/com.apple.SoftwareUpdate",
            "CriticalUpdateInstall",
        )

    @staticmethod
    def _needs_admin(out: str) -> bool:
        # systemsetup prints this when not run as root; the agent daemon runs as
        # root so this only trips in unprivileged test/dev contexts.
        return "administrator access" in out.lower()

    def _network_time(self) -> bool | None:
        out = _run(["systemsetup", "-getusingnetworktime"])
        if self._needs_admin(out):
            return None
        low = out.lower()
        if "on" in low:
            return True
        if "off" in low:
            return False
        return None

    def _time_server(self) -> str | None:
        out = _run(["systemsetup", "-getnetworktimeserver"])
        if self._needs_admin(out):
            return None
        # "Network Time Server: time.apple.com"
        if ":" in out:
            return out.split(":", 1)[1].strip() or None
        return out.strip() or None

    def _file_sharing(self) -> bool | None:
        """SMB file sharing service."""
        return self._svc_loaded("com.apple.smbd")

    def _printer_sharing(self) -> bool | None:
        out = _run(["cupsctl"])
        for line in out.splitlines():
            if "_share_printers" in line:
                return line.strip().endswith("=1")
        return None


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

    # Per-user dotfiles, relative to each home directory. `~/.ssh/authorized_keys`
    # and the shell rc files are prime persistence/backdoor spots — they must be
    # checked for EVERY real user, not just whatever `~` resolves to.
    _USER_DOTFILES = (
        ".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile",
        ".ssh/config", ".ssh/authorized_keys",
    )

    # System-wide configs (absolute), scanned once.
    _SYSTEM_PATHS = (
        "/etc/hosts",
        "/etc/zshrc",
        "/etc/bashrc",
        "/etc/ssh/sshd_config",
        "/etc/pam.d/sudo",
        "/private/etc/sudoers",
    )

    def _home_dirs(self) -> list[str]:
        """Every real user's home — NOT just os.path.expanduser('~').

        Under the root LaunchDaemon the agent's `~` is `/var/root`, so the old
        single-home scan saw only root's (empty) dotfiles and was blind to every
        console user's shell rc and authorized_keys. Enumerate /Users/* plus
        root's own home so per-user persistence is actually visible.
        """
        homes: list[str] = []
        try:
            for entry in sorted(os.listdir("/Users")):
                if entry == "Shared" or entry.startswith("."):
                    continue
                p = os.path.join("/Users", entry)
                if os.path.isdir(p):
                    homes.append(p)
        except OSError:
            pass
        if os.path.isdir("/var/root"):
            homes.append("/var/root")
        # Always include the daemon's own resolved home as a backstop (covers
        # non-standard setups / dev runs where the user isn't under /Users).
        own = os.path.expanduser("~")
        if os.path.isdir(own) and own not in homes:
            homes.append(own)
        return homes

    def collect(self) -> list:
        targets: list[str] = list(self._SYSTEM_PATHS)
        for home in self._home_dirs():
            for rel in self._USER_DOTFILES:
                targets.append(os.path.join(home, rel))

        rows: list[dict] = []
        seen: set[str] = set()
        for path in targets:
            if path in seen:
                continue
            seen.add(path)
            try:
                with open(path) as f:
                    content = f.read(self._READ_LIMIT)
            except OSError:
                continue
            rows.append({
                "path":       path,           # path itself identifies the user
                "content":    content,
                "suspicious": bool(self._SUSPICIOUS_RE.search(content)),
            })
        return rows
