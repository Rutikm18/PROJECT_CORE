"""
manager/manager/queue/schemas.py — Queue topology constants and message builders.

Queue topology
--------------
    Exchange: mac_intel.direct  (direct, durable)
        routing_key "telemetry" → queue "agent.telemetry"  (durable)
        routing_key "jarvis"    → queue "jarvis.work"       (durable)

    Dead Letter Exchange: mac_intel.dlx  (fanout, durable)
        all rejected / expired messages → queue "mac_intel.dead"

Message versions
----------------
    v=1  current format

    agent.telemetry  →  built by build_telemetry_msg()
    jarvis.work      →  built by build_jarvis_msg()
"""
from __future__ import annotations

import time
from typing import Any

# ── Exchange / queue names ────────────────────────────────────────────────────
EXCHANGE_MAIN = "mac_intel.direct"
EXCHANGE_DLX  = "mac_intel.dlx"

QUEUE_TELEMETRY = "agent.telemetry"
QUEUE_JARVIS    = "jarvis.work"
QUEUE_DEAD      = "mac_intel.dead"

ROUTING_TELEMETRY = "telemetry"
ROUTING_JARVIS    = "jarvis"

# ── Queue settings ────────────────────────────────────────────────────────────
MSG_TTL_MS          = 3_600_000   # 1 h — drop messages older than this
QUEUE_MAX_TELEMETRY = 200_000     # ~200k agent payloads buffered max
QUEUE_MAX_JARVIS    = 50_000      # jarvis is slower, smaller buffer


# ── Message builders ──────────────────────────────────────────────────────────

def build_telemetry_msg(
    *,
    agent_id:    str,
    agent_name:  str,
    hostname:    str,
    os_name:     str,
    section:     str,
    collected_at: float,
    client_ip:   str,
    data:        Any,
) -> dict:
    return {
        "v":            1,
        "agent_id":     agent_id,
        "agent_name":   agent_name,
        "hostname":     hostname,
        "os":           os_name,
        "section":      section,
        "collected_at": collected_at,
        "received_at":  time.time(),
        "client_ip":    client_ip,
        "data":         data,
    }


def build_jarvis_msg(
    *,
    agent_id:     str,
    section:      str,
    collected_at: float,
    data:         Any,
    chunk_set_id: str = "",
    chunk_index:  int = 0,
    chunk_total:  int = 1,
) -> dict:
    return {
        "v":            1,
        "agent_id":     agent_id,
        "section":      section,
        "collected_at": collected_at,
        "data":         data,
        "chunk_set_id": chunk_set_id,
        "chunk_index":  chunk_index,
        "chunk_total":  chunk_total,
    }
