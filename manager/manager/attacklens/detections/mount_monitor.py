"""
manager/manager/attacklens/detections/mount_monitor.py
New-mount / removable-media / network-share detection.

Closes a coverage gap: the `mounts` and `storage` sections were stored but had
no dedicated detector (only the universal rulepack). A newly-appearing mount is a
real security event:
  • removable media (USB / external disk)  → T1091 Replication via Removable Media,
                                              T1052 Exfiltration Over Physical Medium
  • network share (SMB / NFS / CIFS / AFP)  → T1021.002 SMB Admin Shares, data staging
  • a new local volume at an unusual path   → data staging / rogue mount

First-run seeding (FP fix): the FIRST time we see an agent's mounts we record the
baseline silently and emit nothing — only mounts appearing AFTER the baseline
fire. Uses DB-backed entity_state so the baseline survives restarts.

Sections handled: mounts, storage. Contract: `analyze(agent_id, section, data, db,
hostname) -> list[dict]` in engine finding format.
"""
from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

log = logging.getLogger("manager.attacklens.detections.mount_monitor")

MOUNT_SECTIONS: frozenset[str] = frozenset({"mounts", "storage"})

# entity_state category + a per-agent sentinel marking "baseline captured".
_CATEGORY = "mount"
_SENTINEL = "mount:__baselined__"

# Network filesystems → remote share (staging / lateral movement surface).
_NETWORK_FS = {"smbfs", "smb", "cifs", "nfs", "afpfs", "webdav", "ftp", "sshfs"}
# Filesystems that typically indicate removable/foreign media on macOS/Windows.
_REMOVABLE_FS = {"msdos", "exfat", "ntfs", "vfat", "fat32", "udf", "iso9660", "hfs"}

SEVERITY_SCORES = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 1.0}

# Cleared per-dispatch by the engine; kept for parity with the other modules.
_dedup_cache: dict = {}


def _rows(data: Any) -> list[dict]:
    """Accept either a raw list of mounts or a {'data': [...]} / {'mounts': [...]} wrapper."""
    if isinstance(data, list):
        return [m for m in data if isinstance(m, dict)]
    if isinstance(data, dict):
        for k in ("data", "mounts", "volumes", "items"):
            v = data.get(k)
            if isinstance(v, list):
                return [m for m in v if isinstance(m, dict)]
    return []


def _key(m: dict) -> str:
    return (m.get("mountpoint") or m.get("device") or "").strip()


def _fingerprint(m: dict) -> str:
    basis = f"{m.get('device','')}|{m.get('mountpoint','')}|{m.get('fstype','')}"
    return hashlib.sha256(basis.encode()).hexdigest()[:16]


def _classify(m: dict) -> tuple[str, str, str, str]:
    """Return (severity, mitre_technique, mitre_tactic, kind) for a new mount."""
    fs = (m.get("fstype") or "").lower()
    mp = (m.get("mountpoint") or "").lower()
    dev = (m.get("device") or "").lower()
    if fs in _NETWORK_FS or dev.startswith("//") or "://" in dev:
        return "high", "T1021.002", "Lateral Movement", "network_share"
    if fs in _REMOVABLE_FS or mp.startswith("/volumes/") or dev.startswith(r"\\.\physicaldrive"):
        return "high", "T1091", "Lateral Movement", "removable_media"
    return "medium", "T1074", "Collection", "new_local_mount"


async def analyze(agent_id: str, section: str, data: Any, db, hostname: str = "") -> list[dict]:
    if section not in MOUNT_SECTIONS:
        return []
    rows = _rows(data)
    if not rows:
        return []

    now = time.time()
    findings: list[dict] = []

    # First-run seeding: if the agent has no baseline sentinel, record every
    # current mount silently and emit nothing (prevents a "new mount" storm on
    # first contact). Best-effort — a db hiccup must not crash detection.
    try:
        seeded = await db.get_entity_state(agent_id, _CATEGORY, _SENTINEL)
    except Exception:
        seeded = None

    for m in rows:
        key = _key(m)
        if not key:
            continue
        ent = f"{_CATEGORY}:{key}"
        try:
            prev = await db.get_entity_state(agent_id, _CATEGORY, ent)
        except Exception:
            prev = None

        if not seeded:
            # baseline capture — remember, don't alert
            try:
                await db.set_entity_state(agent_id, _CATEGORY, ent, _fingerprint(m), now)
            except Exception:
                pass
            continue

        if prev is None:
            # genuinely new mount that appeared after the baseline → alert
            sev, tech, tactic, kind = _classify(m)
            findings.append({
                "rule_id":   f"mount:new_{kind}",
                "severity":  sev,
                "title":     f"New {kind.replace('_', ' ')} mounted: {key}",
                "description": (
                    f"A new mount appeared on {hostname or agent_id} that was not present "
                    f"in the baseline: device={m.get('device')!r} at {m.get('mountpoint')!r} "
                    f"(fstype={m.get('fstype')!r}). New {kind.replace('_',' ')} mounts are a "
                    f"data-staging / exfiltration vector."
                ),
                "evidence": {
                    "device":     m.get("device"),
                    "mountpoint": m.get("mountpoint"),
                    "fstype":     m.get("fstype"),
                    "options":    m.get("options"),
                    "kind":       kind,
                },
                "mitre_tactic":    tactic,
                "mitre_technique": tech,
                "recommended_action": (
                    f"Confirm the mount at {m.get('mountpoint')!r} is authorized. "
                    "For removable media, verify the device and scan its contents; for a "
                    "network share, confirm the remote host and that the mount is expected."
                ),
                "false_positive_notes": (
                    "Routine external-drive/USB usage and expected network shares trigger this. "
                    "Baseline-known mounts never re-fire; only mounts new since baseline do."
                ),
                "item_key":  f"mount:{key}",
                "category":  "mount",
                "source":    "rule:mount_monitor",
                "score":     SEVERITY_SCORES.get(sev, 5.0),
                "confidence": 0.6,
                "tags":      ["mount", kind, tech],
            })
            try:
                await db.set_entity_state(agent_id, _CATEGORY, ent, _fingerprint(m), now)
            except Exception:
                pass

    # Mark the agent baselined after the first pass.
    if not seeded:
        try:
            await db.set_entity_state(agent_id, _CATEGORY, _SENTINEL, "1", now)
        except Exception:
            pass

    return findings
