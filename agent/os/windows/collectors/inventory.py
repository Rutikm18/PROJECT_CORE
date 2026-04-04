"""
agent/os/windows/collectors/inventory.py — Software inventory (10 min – 24 hr).

sections: storage, tasks, apps, packages, binaries, sbom

Design notes
────────────
• apps     — reads the Uninstall registry hive directly via winreg (three locations:
              HKLM 64-bit, HKLM WoW64 32-bit, HKCU) to enumerate all installed software.
• tasks    — Get-ScheduledTask PowerShell; schtasks /query CSV fallback.
• packages — pip, npm, choco, winget, scoop — each is optional; missing tools are
             silently skipped.
• binaries — walks %ProgramFiles%, %ProgramFiles(x86)%, %SystemRoot%\System32 for
             .exe files; SHA-256 computed on first 4 MiB only (performance cap).
• sbom     — aggregates pip, npm, choco, winget into purl-formatted records.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re

import psutil

from .base import WinBaseCollector

log = logging.getLogger("agent.windows.collectors.inventory")


# ── storage ───────────────────────────────────────────────────────────────────

class StorageCollector(WinBaseCollector):
    name    = "storage"
    timeout = 15

    def collect(self) -> list:
        results: list[dict] = []
        try:
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                except (PermissionError, OSError):
                    continue
                results.append({
                    "device":     part.device,
                    "mountpoint": part.mountpoint,
                    "fstype":     part.fstype or None,
                    "total_gb":   round(usage.total / 1e9, 3),
                    "used_gb":    round(usage.used  / 1e9, 3),
                    "free_gb":    round(usage.free  / 1e9, 3),
                    "pct":        round(usage.percent, 2),
                })
        except Exception as exc:
            log.debug("storage: %s", exc)
        return results


# ── tasks ─────────────────────────────────────────────────────────────────────

class TasksCollector(WinBaseCollector):
    name    = "tasks"
    timeout = 45

    def collect(self) -> list:
        tasks: list[dict] = []

        # Primary: Get-ScheduledTask (Windows 8+ / Server 2012+)
        ps_out = self._run_ps(
            "Get-ScheduledTask | "
            "Select-Object TaskName,TaskPath,State,"
            "@{N='Execute';E={$_.Actions | Select-Object -First 1 -ExpandProperty Execute}},"
            "@{N='Arguments';E={$_.Actions | Select-Object -First 1 -ExpandProperty Arguments}},"
            "@{N='Trigger';E={$_.Triggers | Select-Object -First 1 | ConvertTo-Json -Compress -Depth 2}} "
            "| ConvertTo-Json -Compress"
        )
        try:
            items = json.loads(ps_out.strip() or "[]")
            if isinstance(items, dict):
                items = [items]
            for item in items or []:
                state   = (item.get("State") or "Unknown").lower()
                enabled = state in ("ready", "running")
                cmd     = item.get("Execute") or ""
                args    = item.get("Arguments") or ""
                command = (f"{cmd} {args}".strip()) or None

                schedule = None
                try:
                    trg = item.get("Trigger")
                    if trg:
                        td = json.loads(trg) if isinstance(trg, str) else (trg or {})
                        # Use StartBoundary or CimClassName as schedule description
                        schedule = str(
                            td.get("StartBoundary") or
                            td.get("CimClass", {}).get("CimClassName") or ""
                        ) or None
                except Exception:
                    pass

                tasks.append({
                    "name":     (item.get("TaskPath") or "\\") + (item.get("TaskName") or ""),
                    "type":     "schtasks",
                    "schedule": schedule,
                    "command":  command,
                    "user":     None,
                    "enabled":  enabled,
                    "last_run": None,
                    "next_run": None,
                })
        except Exception as exc:
            log.debug("tasks PS: %s", exc)
            # CSV fallback
            raw = self._run(["schtasks", "/query", "/fo", "CSV", "/v"])
            lines = raw.splitlines()
            if lines:
                header = [h.strip('"') for h in lines[0].split(",")]
                for line in lines[1:]:
                    if not line.strip():
                        continue
                    parts = [p.strip('"') for p in line.split(",")]
                    if len(parts) < len(header):
                        continue
                    row = dict(zip(header, parts))
                    status = (row.get("Status") or "").lower()
                    tasks.append({
                        "name":     row.get("TaskName", ""),
                        "type":     "schtasks",
                        "schedule": row.get("Schedule Type"),
                        "command":  row.get("Task To Run"),
                        "user":     row.get("Run As User"),
                        "enabled":  status not in ("disabled",),
                        "last_run": None,
                        "next_run": None,
                    })

        return tasks


# ── apps ──────────────────────────────────────────────────────────────────────

class AppsCollector(WinBaseCollector):
    """
    Read installed applications from the Windows Uninstall registry hives.

    Three hive locations cover 64-bit apps, 32-bit apps (WoW64 redirect),
    and per-user installs respectively.
    """
    name    = "apps"
    timeout = 20

    def collect(self) -> list:
        try:
            import winreg
        except ImportError:
            return []

        hklm = winreg.HKEY_LOCAL_MACHINE
        hkcu = winreg.HKEY_CURRENT_USER
        UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        WOW6432   = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

        apps: list[dict] = []
        seen: set[str]   = set()

        for hive, path in [
            (hklm, UNINSTALL),
            (hklm, WOW6432),
            (hkcu, UNINSTALL),
        ]:
            for key_name in self.reg_enum_keys(hive, path):
                sub = f"{path}\\{key_name}"
                name = _rv(hive, sub, "DisplayName")
                if not name or name in seen:
                    continue
                seen.add(name)

                version   = _rv(hive, sub, "DisplayVersion")
                publisher = _rv(hive, sub, "Publisher")
                inst_loc  = _rv(hive, sub, "InstallLocation")
                inst_date = _rv(hive, sub, "InstallDate")

                installed_at = None
                if inst_date:
                    try:
                        from datetime import datetime
                        installed_at = int(
                            datetime.strptime(str(inst_date).strip(), "%Y%m%d").timestamp()
                        )
                    except Exception:
                        pass

                apps.append({
                    "name":         name,
                    "version":      version,
                    "bundle_id":    None,   # macOS concept
                    "path":         inst_loc or None,
                    "signed":       None,   # Authenticode check would add latency
                    "notarized":    None,   # macOS only
                    "vendor":       publisher,
                    "installed_at": installed_at,
                })

        return apps


# ── packages ──────────────────────────────────────────────────────────────────

class PackagesCollector(WinBaseCollector):
    name    = "packages"
    timeout = 60

    def collect(self) -> list:
        packages: list[dict] = []
        packages.extend(self._pip())
        packages.extend(self._npm())
        packages.extend(self._choco())
        packages.extend(self._winget())
        packages.extend(self._scoop())
        return packages

    def _pip(self) -> list:
        out = self._run(["pip", "list", "--format=json"])
        try:
            return [
                {"manager": "pip", "name": p["name"], "version": p.get("version"),
                 "latest": None, "outdated": None, "installed_at": None}
                for p in (json.loads(out) or [])
            ]
        except Exception:
            return []

    def _npm(self) -> list:
        out = self._run(["npm", "list", "-g", "--depth=0", "--json"])
        try:
            d = json.loads(out)
            return [
                {"manager": "npm", "name": name, "version": info.get("version"),
                 "latest": None, "outdated": None, "installed_at": None}
                for name, info in (d.get("dependencies") or {}).items()
            ]
        except Exception:
            return []

    def _choco(self) -> list:
        out = self._run(["choco", "list", "--local-only", "--limit-output"])
        results: list[dict] = []
        for line in out.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 2:
                results.append({
                    "manager": "choco", "name": parts[0], "version": parts[1],
                    "latest": None, "outdated": None, "installed_at": None,
                })
        return results

    def _winget(self) -> list:
        out = self._run(["winget", "list",
                         "--accept-source-agreements", "--disable-interactivity"])
        results: list[dict] = []
        lines  = out.splitlines()
        # Skip two header lines (name/version/id row + dashes row)
        data_start = next(
            (i for i, l in enumerate(lines) if re.match(r"^-{3,}", l.strip())), -1
        )
        if data_start < 0:
            return results
        for line in lines[data_start + 1:]:
            line = line.strip()
            if not line:
                continue
            # winget columns are fixed-width; split on 2+ spaces is more reliable
            parts = re.split(r"\s{2,}", line)
            if len(parts) < 2:
                continue
            results.append({
                "manager": "winget", "name": parts[0],
                "version": parts[1] if len(parts) > 1 else None,
                "latest": None, "outdated": None, "installed_at": None,
            })
        return results

    def _scoop(self) -> list:
        out = self._run(["scoop", "list"])
        results: list[dict] = []
        for line in out.strip().splitlines()[2:]:   # skip header rows
            parts = line.split()
            if len(parts) >= 2:
                results.append({
                    "manager": "scoop", "name": parts[0], "version": parts[1],
                    "latest": None, "outdated": None, "installed_at": None,
                })
        return results


# ── binaries ──────────────────────────────────────────────────────────────────

class BinariesCollector(WinBaseCollector):
    """
    Walk standard binary directories for PE (.exe) files.

    SHA-256 is computed on the first HASH_CAP bytes only — reading entire
    large executables would be too slow and is not needed for deduplication.
    """
    name    = "binaries"
    timeout = 90

    _MAX_FILES: int = 500
    _HASH_CAP:  int = 4 * 1024 * 1024   # 4 MiB

    _SCAN_DIRS: list[str] = [
        os.environ.get("ProgramFiles",      r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        os.environ.get("SystemRoot",        r"C:\Windows") + r"\System32",
    ]

    def collect(self) -> list:
        results: list[dict] = []
        seen: set[str]      = set()

        for base_dir in self._SCAN_DIRS:
            if not base_dir or not os.path.isdir(base_dir):
                continue
            for root, dirs, files in os.walk(base_dir):
                # Skip deep Windows side-by-side assembly trees
                dirs[:] = [d for d in dirs if d.lower() != "winsxs"]
                for fname in files:
                    if not fname.lower().endswith(".exe"):
                        continue
                    if len(results) >= self._MAX_FILES:
                        return results
                    fpath = os.path.join(root, fname)
                    if fpath in seen:
                        continue
                    seen.add(fpath)
                    try:
                        st  = os.stat(fpath)
                        sha = _sha256_partial(fpath, self._HASH_CAP)
                        results.append({
                            "path":          fpath,
                            "name":          fname,
                            "hash_sha256":   sha,
                            "size_bytes":    st.st_size,
                            "modified_at":   int(st.st_mtime),
                            "signed":        None,   # Authenticode skipped (latency)
                            "notarized":     None,
                            "permissions":   None,
                            "owner":         None,
                            "suid":          None,
                            "sgid":          None,
                            "world_writable":None,
                        })
                    except (PermissionError, OSError):
                        continue

        return results


# ── sbom ──────────────────────────────────────────────────────────────────────

class SbomCollector(WinBaseCollector):
    """Software Bill of Materials — aggregates pip, npm, choco, winget."""
    name    = "sbom"
    timeout = 60

    def collect(self) -> list:
        components: list[dict] = []

        # pip
        out = self._run(["pip", "list", "--format=json"])
        try:
            for p in json.loads(out) or []:
                name = p.get("name", "")
                ver  = p.get("version")
                components.append({
                    "type":    "library",
                    "name":    name,
                    "version": ver,
                    "purl":    f"pkg:pypi/{name.lower()}@{ver}" if ver else None,
                    "license": None,
                    "source":  "pip",
                    "cpe":     None,
                })
        except Exception:
            pass

        # npm
        out = self._run(["npm", "list", "-g", "--depth=0", "--json"])
        try:
            d = json.loads(out)
            for name, info in (d.get("dependencies") or {}).items():
                ver = info.get("version")
                components.append({
                    "type":    "library",
                    "name":    name,
                    "version": ver,
                    "purl":    f"pkg:npm/{name}@{ver}" if ver else None,
                    "license": None,
                    "source":  "npm",
                    "cpe":     None,
                })
        except Exception:
            pass

        # choco
        out = self._run(["choco", "list", "--local-only", "--limit-output"])
        for line in out.strip().splitlines():
            parts = line.split("|")
            if len(parts) >= 2:
                name, ver = parts[0], parts[1]
                components.append({
                    "type":    "application",
                    "name":    name,
                    "version": ver,
                    "purl":    f"pkg:chocolatey/{name.lower()}@{ver}",
                    "license": None,
                    "source":  "choco",
                    "cpe":     None,
                })

        # winget
        out = self._run(["winget", "export", "-o", "-",
                         "--accept-source-agreements",
                         "--disable-interactivity"])
        try:
            d = json.loads(out)
            for src in d.get("Sources", []):
                for pkg in src.get("Packages", []):
                    pid  = pkg.get("PackageIdentifier", "")
                    ver  = pkg.get("Version")
                    components.append({
                        "type":    "application",
                        "name":    pid,
                        "version": ver,
                        "purl":    f"pkg:winget/{pid}@{ver}" if ver else None,
                        "license": None,
                        "source":  "winget",
                        "cpe":     None,
                    })
        except Exception:
            pass

        return components


# ── helpers ───────────────────────────────────────────────────────────────────

def _rv(hive, path: str, name: str):
    """Read a single registry value; return None on error."""
    try:
        import winreg
        with winreg.OpenKey(hive, path, 0,
                            winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            val, _ = winreg.QueryValueEx(k, name)
            return val
    except Exception:
        return None


def _sha256_partial(path: str, cap: int) -> str | None:
    """SHA-256 of the first `cap` bytes of a file. Returns None on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            h.update(f.read(cap))
        return h.hexdigest()
    except Exception:
        return None
