"""
manager/manager/queue/schemas.py — Queue topology constants and message builders.

Queue topology
--------------
    Exchange: mac_intel.direct  (direct, durable)
        routing_key "telemetry"  → queue "agent.telemetry"    (durable)
        routing_key "attacklens" → queue "attacklens.work"    (durable)

    Dead Letter Exchange: mac_intel.dlx  (fanout, durable)
        all rejected / expired messages → queue "mac_intel.dead"

Message versions
----------------
    v=1  current format

    agent.telemetry   →  built by build_telemetry_msg()
    attacklens.work   →  built by build_attacklens_msg()
"""
from __future__ import annotations

import time
import uuid
from typing import Any

# ── Exchange / queue names ────────────────────────────────────────────────────
EXCHANGE_MAIN = "mac_intel.direct"
EXCHANGE_DLX  = "mac_intel.dlx"
EXCHANGE_RETRY = "mac_intel.retry"
EXCHANGE_PARKING = "mac_intel.parking"

QUEUE_TELEMETRY  = "agent.telemetry"
QUEUE_ATTACKLENS = "attacklens.work"
QUEUE_DEAD       = "mac_intel.dead"
QUEUE_PARKED     = "mac_intel.parked"

ROUTING_TELEMETRY  = "telemetry"
ROUTING_ATTACKLENS = "attacklens"
ROUTING_PARKED     = "parked"

# ── Queue settings ────────────────────────────────────────────────────────────
QUEUE_MAX_TELEMETRY  = 200_000     # ~200k agent payloads buffered max
QUEUE_MAX_ATTACKLENS = 50_000      # detection engine is slower, smaller buffer
RETRY_DELAYS_MS      = (5_000, 15_000, 60_000)


def retry_routing_key(origin_routing_key: str, delay_ms: int) -> str:
    return f"{origin_routing_key}.{int(delay_ms)}"


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
    event_id:    str = "",
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
        "event_id":     event_id or uuid.uuid4().hex,
    }


def build_attacklens_msg(
    *,
    agent_id:     str,
    section:      str,
    collected_at: float,
    data:         Any,
    event_id:     str = "",
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
        "event_id":     event_id or chunk_set_id or uuid.uuid4().hex,
        "chunk_set_id": chunk_set_id,
        "chunk_index":  chunk_index,
        "chunk_total":  chunk_total,
    }
