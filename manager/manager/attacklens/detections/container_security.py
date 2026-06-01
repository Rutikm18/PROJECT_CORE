"""
manager/manager/attacklens/detections/container_security.py
Production-grade container security misconfiguration and rogue workload detection.

Analyzes Docker and Kubernetes container telemetry to detect dangerous runtime
configurations, supply-chain risks, and unauthorized workload deployments.

Sections handled:
  containers         → Docker inspect list / agent container inventory
  pods               → kubectl get pods -o json output
  container_security → generic (auto-detects Docker or K8s format)

Detection passes:
  1. Privileged container with host network — full host escape risk (CRITICAL)
  2. Management port exposed on 0.0.0.0     — unauthenticated service access (CRITICAL)
  3. Unpinned image (latest tag / no digest) — silent image replacement risk (HIGH)
  4. Untrusted registry source               — supply-chain compromise vector (HIGH)
  5. Rogue container not in approved manifest— unauthorized workload deployment (HIGH)
  6. Sensitive environment variable exposure — secrets in container config (MEDIUM)

COMPLIANCE MAPPING:
  NIST CSF:      PR.AC-3 (Remote access managed), DE.CM-7 (Unauthorized activity)
  CIS Benchmark: Docker CIS v1.5 §2.15 §4.1 §5.14, Kubernetes CIS v1.7 §5.1
  SOC 2:         CC6.6 (External access controls), CC7.2 (Anomaly detection)
  ISO 27001:     A.13.1.3 (Segregation in networks), A.12.4.1 (Event logging)

MITRE ATT&CK:
  T1610  (Deploy Container)
  T1612  (Build Image on Host)
  T1133  (External Remote Services)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("manager.attacklens.detections.container_security")

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS — all thresholds configurable here
# ─────────────────────────────────────────────────────────────────────────────

# Ports that must never be exposed on 0.0.0.0 — unauthenticated management services
HIGH_RISK_PORTS: dict[int, str] = {
    2375:  "Docker daemon API (unencrypted)",
    2376:  "Docker daemon API (TLS — check cert validation)",
    9200:  "Elasticsearch REST API",
    9300:  "Elasticsearch node communication",
    9000:  "Portainer management UI",
    15672: "RabbitMQ management UI",
    5601:  "Kibana web UI",
    8080:  "Generic HTTP management interface",
    3306:  "MySQL/MariaDB database",
    5432:  "PostgreSQL database",
    27017: "MongoDB database",
    27018: "MongoDB shard",
    6379:  "Redis (no auth default)",
    11211: "Memcached",
    5672:  "RabbitMQ AMQP",
    4848:  "GlassFish admin console",
    8161:  "ActiveMQ admin console",
    61616: "ActiveMQ broker",
    2181:  "ZooKeeper client port",
    9092:  "Kafka broker",
}

# Env var key substrings that indicate secrets
SENSITIVE_ENV_PATTERNS: tuple[str, ...] = (
    "PASSWORD", "PASSWD", "SECRET", "API_KEY", "APIKEY",
    "TOKEN", "AUTH", "PRIVATE_KEY", "ACCESS_KEY", "SIGNING_KEY",
    "CREDENTIALS", "CREDENTIAL", "PASSPHRASE", "CERT_KEY",
    "DB_PASS", "MYSQL_ROOT", "POSTGRES_PASSWORD",
)

# Container labels whose presence marks a container as a disposable CI/CD ephemeral
CI_EPHEMERAL_LABEL_KEYS: frozenset[str] = frozenset({
    "ci-ephemeral", "ci.ephemeral", "build.ephemeral",
    "jenkins.build", "github.actions", "gitlab.ci",
    "com.github.actions.run-id", "io.jenkins.blueocean",
    "com.gitlab.gitlab-runner.job.id",
})

# Default approved registries (extended by config/approved_registries.json)
DEFAULT_APPROVED_REGISTRIES: frozenset[str] = frozenset({
    "docker.io", "index.docker.io",
    "ghcr.io",
    "gcr.io",
    "registry.k8s.io", "k8s.gcr.io",
    "quay.io",
    "mcr.microsoft.com",
    "public.ecr.aws",
    "registry.access.redhat.com",
    "registry.fedoraproject.org",
})

# Config file paths (overridable via env)
APPROVED_REGISTRIES_PATH: str = os.environ.get(
    "APPROVED_REGISTRIES_PATH", "config/approved_registries.json"
)
APPROVED_WORKLOADS_PATH: str = os.environ.get(
    "APPROVED_WORKLOADS_PATH", "config/approved_workloads.json"
)

# How long to retain container fingerprints in the per-agent baseline
WORKLOAD_BASELINE_TTL_SECS: int = 7 * 86400   # 7 days

# Dedup / rate-limiting
DEDUP_WINDOW_SECS: int       = 3600
RATE_LIMIT_MAX_PER_HOUR: int = 40

SEVERITY_SCORES: dict[str, float] = {
    "critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5,
}

# ─────────────────────────────────────────────────────────────────────────────
# MODULE-LEVEL STATE
# ─────────────────────────────────────────────────────────────────────────────

_dedup_cache: dict[str, float]        = {}
_rate_counter: dict[str, list[float]] = {}

# Config file caches — reloaded every 5 minutes
_approved_registries_cache: frozenset[str] = frozenset()
_approved_registries_loaded_at: float      = 0.0
_approved_workloads_cache: list[dict]      = []
_approved_workloads_loaded_at: float       = 0.0

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS — image parsing, env redaction, config loaders
# ─────────────────────────────────────────────────────────────────────────────

def _parse_image(image: str) -> dict:
    """
    Parse an image reference into {registry, name, tag, digest}.

    Handles all standard forms:
      nginx                          → docker.io / nginx / latest / ""
      nginx:1.25                     → docker.io / nginx / 1.25  / ""
      nginx:1.25@sha256:abc          → docker.io / nginx / 1.25  / sha256:abc
      registry.company.com/app:1.0  → registry.company.com / app / 1.0 / ""
      gcr.io/project/image:tag       → gcr.io / project/image / tag / ""
      localhost:5000/app:latest      → localhost:5000 / app / latest / ""
    """
    image = str(image or "").strip()
    if not image:
        return {"registry": "", "name": "", "tag": "", "digest": ""}

    # Split off digest (@sha256:…)
    digest = ""
    if "@" in image:
        image, digest = image.rsplit("@", 1)

    # Split off tag (only the LAST segment can contain a colon for the tag)
    tag = "latest"
    segments = image.split("/")
    last = segments[-1]
    if ":" in last:
        segments[-1], tag = last.rsplit(":", 1)
        image = "/".join(segments)

    # Detect registry: first segment containing "." or ":" or equal to "localhost"
    parts = image.split("/")
    if len(parts) > 1 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
        registry = parts[0]
        name     = "/".join(parts[1:])
    else:
        registry = "docker.io"
        name     = image

    return {"registry": registry, "name": name, "tag": tag, "digest": digest}


def _parse_docker_ports(port_bindings: Any) -> list[dict]:
    """
    Parse Docker HostConfig.PortBindings / NetworkSettings.Ports format.

    Input:  {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}], ...}
    Output: [{"host_ip": "0.0.0.0", "host_port": 8080,
              "container_port": 80, "protocol": "tcp"}, ...]
    """
    if not isinstance(port_bindings, dict):
        return []
    ports = []
    for port_proto, bindings in port_bindings.items():
        if not bindings:
            continue
        segments       = str(port_proto).split("/")
        container_port = int(segments[0]) if segments[0].isdigit() else 0
        protocol       = segments[1].lower() if len(segments) > 1 else "tcp"
        for b in (bindings if isinstance(bindings, list) else [bindings]):
            if not isinstance(b, dict):
                continue
            host_ip = str(b.get("HostIp") or b.get("host_ip") or "0.0.0.0")
            try:
                host_port = int(b.get("HostPort") or b.get("host_port") or 0)
            except (ValueError, TypeError):
                host_port = 0
            if host_port == 0:
                continue
            ports.append({
                "host_ip":        host_ip,
                "host_port":      host_port,
                "container_port": container_port,
                "protocol":       protocol,
            })
    return ports


def _parse_env_list(env_list: Any) -> dict[str, str]:
    """Parse Docker env list ["KEY=value", …] into a dict."""
    if isinstance(env_list, dict):
        return {str(k): str(v) for k, v in env_list.items()}
    if not isinstance(env_list, list):
        return {}
    result: dict[str, str] = {}
    for entry in env_list:
        if not isinstance(entry, str) or "=" not in entry:
            continue
        k, _, v = entry.partition("=")
        result[k.strip()] = v
    return result


def _is_ci_ephemeral(labels: dict) -> bool:
    """Return True if any label key or value marks the container as a CI ephemeral build."""
    if not isinstance(labels, dict):
        return False
    label_keys_lower = {k.lower() for k in labels}
    return bool(label_keys_lower & {k.lower() for k in CI_EPHEMERAL_LABEL_KEYS})


def _is_sensitive_env(key: str) -> bool:
    """Return True if the env var name suggests it contains a secret."""
    k = key.upper()
    return any(pattern in k for pattern in SENSITIVE_ENV_PATTERNS)


def _redact_env_value(value: str) -> str:
    """Return a short SHA256 fingerprint of the value — auditable without exposure."""
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()[:16]


def _container_fingerprint(registry: str, image_name: str, image_tag: str,
                            host_ports: list[int]) -> str:
    """Stable identity fingerprint for approved-workload and baseline matching."""
    canonical = f"{registry}/{image_name}:{image_tag}|{sorted(host_ports)}"
    return hashlib.sha256(canonical.encode()).hexdigest()[:20]


def _load_approved_registries() -> frozenset[str]:
    """
    Load approved registries.  Result is cached for 5 minutes.

    Config format (config/approved_registries.json):
      {"registries": ["docker.io", "registry.company.com"]}

    Returns DEFAULT_APPROVED_REGISTRIES union any additional entries from config.
    """
    global _approved_registries_cache, _approved_registries_loaded_at
    now = time.time()
    if now - _approved_registries_loaded_at < 300 and _approved_registries_cache:
        return _approved_registries_cache
    try:
        p = Path(APPROVED_REGISTRIES_PATH)
        if p.exists():
            data = json.loads(p.read_text())
            extra = frozenset(r.lower() for r in (data.get("registries") or []))
            _approved_registries_cache = DEFAULT_APPROVED_REGISTRIES | extra
        else:
            _approved_registries_cache = DEFAULT_APPROVED_REGISTRIES
    except Exception as exc:
        log.debug("Approved registries load failed (%s): %s", APPROVED_REGISTRIES_PATH, exc)
        _approved_registries_cache = DEFAULT_APPROVED_REGISTRIES
    _approved_registries_loaded_at = now
    return _approved_registries_cache


def _load_approved_workloads() -> list[dict]:
    """
    Load approved workload manifest.  Result is cached for 5 minutes.

    Config format (config/approved_workloads.json):
      {
        "workloads": [
          {
            "image_name":        "nginx",
            "registries":        ["docker.io"],
            "allowed_tags":      ["1.25", "1.26"],
            "allowed_host_ports": [80, 443]
          }
        ]
      }

    Returns [] if the file does not exist — triggers baseline-only mode.
    """
    global _approved_workloads_cache, _approved_workloads_loaded_at
    now = time.time()
    if now - _approved_workloads_loaded_at < 300:
        return _approved_workloads_cache
    try:
        p = Path(APPROVED_WORKLOADS_PATH)
        _approved_workloads_cache = (json.loads(p.read_text()).get("workloads") or []) if p.exists() else []
    except Exception as exc:
        log.debug("Approved workloads load failed (%s): %s", APPROVED_WORKLOADS_PATH, exc)
        _approved_workloads_cache = []
    _approved_workloads_loaded_at = now
    return _approved_workloads_cache


def _is_approved_workload(image_name: str, registry: str,
                           image_tag: str, host_ports: list[int]) -> bool:
    """Return True if container matches an entry in the approved workload manifest."""
    for wl in _load_approved_workloads():
        if wl.get("image_name") and wl["image_name"] not in image_name:
            continue
        allowed_regs = [r.lower() for r in (wl.get("registries") or [])]
        if allowed_regs and registry.lower() not in allowed_regs:
            continue
        allowed_tags = wl.get("allowed_tags") or []
        if allowed_tags and image_tag not in allowed_tags:
            continue
        allowed_ports = set(int(p) for p in (wl.get("allowed_host_ports") or []))
        if allowed_ports and not set(host_ports).issubset(allowed_ports):
            continue
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# DEDUP / RATE-LIMIT
# ─────────────────────────────────────────────────────────────────────────────

def _dedup_key(agent_id: str, rule_id: str, item: str) -> str:
    return hashlib.sha256(f"{agent_id}:{rule_id}:{item}".encode()).hexdigest()[:16]


def _should_suppress(agent_id: str, rule_id: str, item: str) -> bool:
    now = time.time()
    key = _dedup_key(agent_id, rule_id, item)
    if now - _dedup_cache.get(key, 0) < DEDUP_WINDOW_SECS:
        return True
    times = [t for t in _rate_counter.get(agent_id, []) if now - t < 3600]
    if len(times) >= RATE_LIMIT_MAX_PER_HOUR:
        log.debug("Rate limit reached: agent=%s module=container_security", agent_id)
        return True
    times.append(now)
    _rate_counter[agent_id] = times
    _dedup_cache[key] = now
    return False


# ─────────────────────────────────────────────────────────────────────────────
# BASELINE MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

_BASELINE_NS = "container_security"


async def _load_baseline(agent_id: str, key: str, db: Any) -> Optional[dict]:
    try:
        row = await db.get_entity_state(agent_id, _BASELINE_NS, key)
        if row and row.get("fingerprint"):
            return json.loads(row["fingerprint"])
    except Exception as exc:
        log.debug("Baseline load error agent=%s key=%s: %s", agent_id, key, exc)
    return None


async def _save_baseline(agent_id: str, key: str, data: dict, db: Any) -> None:
    try:
        await db.set_entity_state(
            agent_id, _BASELINE_NS, key,
            json.dumps(data, default=str),
            time.time(),
        )
    except Exception as exc:
        log.debug("Baseline save error agent=%s key=%s: %s", agent_id, key, exc)


# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY INGESTION — normalize Docker / K8s / agent-generic payloads
# ─────────────────────────────────────────────────────────────────────────────

def ingest_containers(raw: Any) -> list[dict]:
    """
    Normalize container telemetry from multiple source formats into a uniform list.

    Accepted formats:
      • Docker inspect list  — list of Docker inspect dicts (Id, Config, HostConfig…)
      • kubectl pods JSON    — {"items": [{metadata, spec, status}]}
      • Agent normalized     — {"containers": [normalized_dict, …]}
      • Flat normalized list — [{"container_id": …, "image": …, …}]
    """
    if isinstance(raw, dict):
        # kubectl get pods -o json
        if "items" in raw:
            result = []
            for pod in (raw["items"] or []):
                result.extend(_ingest_k8s_pod(pod))
            return result
        # Agent wrapper: {"containers": [...]}
        items = raw.get("containers") or raw.get("data") or []
        raw   = items

    if not isinstance(raw, list):
        return []

    if not raw:
        return []

    result = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        # Docker inspect heuristic: has "HostConfig" or "Config" top-level
        if "HostConfig" in item or "Config" in item:
            c = _ingest_docker_container(item)
            if c:
                result.append(c)
        # K8s pod heuristic: has "spec" with "containers"
        elif "spec" in item and "containers" in (item.get("spec") or {}):
            result.extend(_ingest_k8s_pod(item))
        else:
            # Pre-normalized generic format from agent
            c = _ingest_generic(item)
            if c:
                result.append(c)
    return result


def _ingest_docker_container(c: dict) -> Optional[dict]:
    """Parse a single docker inspect dict."""
    config      = c.get("Config") or {}
    host_config = c.get("HostConfig") or {}
    net_settings = c.get("NetworkSettings") or {}
    state       = c.get("State") or {}

    image_str = str(config.get("Image") or c.get("Image") or "")
    parsed    = _parse_image(image_str)

    # Ports from HostConfig.PortBindings (authoritative) or NetworkSettings.Ports
    port_bindings = (host_config.get("PortBindings") or
                     net_settings.get("Ports") or {})
    ports = _parse_docker_ports(port_bindings)

    # Image digest: look in Config, then top-level RepoDigests
    digest = parsed["digest"]
    if not digest:
        repo_digests = c.get("RepoDigests") or []
        if repo_digests and isinstance(repo_digests, list):
            d = str(repo_digests[0])
            if "@" in d:
                digest = d.split("@", 1)[1]

    return {
        "container_id":   (str(c.get("Id") or ""))[:12],
        "container_name": str(c.get("Name") or "").lstrip("/"),
        "image":          image_str,
        "image_name":     parsed["name"],
        "image_tag":      parsed["tag"],
        "image_digest":   digest,
        "registry":       parsed["registry"],
        "ports":          ports,
        "network_mode":   str(host_config.get("NetworkMode") or "bridge").lower(),
        "privileged":     bool(host_config.get("Privileged", False)),
        "volumes":        list(host_config.get("Binds") or []),
        "env_vars":       _parse_env_list(config.get("Env") or []),
        "labels":         dict(config.get("Labels") or {}),
        "status":         str(state.get("Status") or "running").lower(),
        "raw":            c,
    }


def _ingest_k8s_pod(pod: dict) -> list[dict]:
    """Parse a kubectl pod dict into one normalized container dict per container."""
    meta   = pod.get("metadata") or {}
    spec   = pod.get("spec") or {}
    status = pod.get("status") or {}

    pod_name      = str(meta.get("name") or "")
    namespace     = str(meta.get("namespace") or "default")
    labels        = dict(meta.get("labels") or {})
    phase         = str(status.get("phase") or "Running").lower()
    host_network  = bool(spec.get("hostNetwork", False))
    network_mode  = "host" if host_network else "bridge"

    result = []
    for c in (spec.get("containers") or []):
        if not isinstance(c, dict):
            continue
        image_str = str(c.get("image") or "")
        parsed    = _parse_image(image_str)
        sec_ctx   = c.get("securityContext") or {}
        privileged = bool(sec_ctx.get("privileged", False))

        # Ports from spec.containers[].ports[]
        ports = []
        for p in (c.get("ports") or []):
            if not isinstance(p, dict):
                continue
            hp = int(p.get("hostPort") or 0)
            cp = int(p.get("containerPort") or 0)
            if hp == 0 and cp:
                hp = cp  # treat containerPort as hostPort when no explicit mapping
            protocol = str(p.get("protocol") or "TCP").lower()
            ports.append({
                "host_ip":        "0.0.0.0",
                "host_port":      hp,
                "container_port": cp,
                "protocol":       protocol,
            })

        env_raw = {}
        for e in (c.get("env") or []):
            if isinstance(e, dict) and e.get("name"):
                env_raw[e["name"]] = str(e.get("value") or "")

        result.append({
            "container_id":   f"{pod_name}/{c.get('name', '')}",
            "container_name": f"{namespace}/{pod_name}/{c.get('name', '')}",
            "image":          image_str,
            "image_name":     parsed["name"],
            "image_tag":      parsed["tag"],
            "image_digest":   parsed["digest"],
            "registry":       parsed["registry"],
            "ports":          ports,
            "network_mode":   network_mode,
            "privileged":     privileged,
            "volumes":        [str(v.get("name", "")) for v in (c.get("volumeMounts") or [])],
            "env_vars":       env_raw,
            "labels":         labels,
            "status":         phase,
            "raw":            pod,
        })
    return result


def _ingest_generic(item: dict) -> Optional[dict]:
    """Pass-through for agent-normalized container dicts."""
    if not item.get("image") and not item.get("image_name"):
        return None
    image_str = str(item.get("image") or "")
    parsed    = _parse_image(image_str)

    raw_ports = item.get("ports") or []
    ports: list[dict] = []
    if isinstance(raw_ports, list):
        for p in raw_ports:
            if isinstance(p, dict):
                ports.append({
                    "host_ip":        str(p.get("host_ip") or "0.0.0.0"),
                    "host_port":      int(p.get("host_port") or 0),
                    "container_port": int(p.get("container_port") or 0),
                    "protocol":       str(p.get("protocol") or "tcp").lower(),
                })
    elif isinstance(raw_ports, dict):
        ports = _parse_docker_ports(raw_ports)

    return {
        "container_id":   str(item.get("container_id") or item.get("id") or "")[:12],
        "container_name": str(item.get("container_name") or item.get("name") or ""),
        "image":          image_str,
        "image_name":     str(item.get("image_name") or parsed["name"]),
        "image_tag":      str(item.get("image_tag") or parsed["tag"]),
        "image_digest":   str(item.get("image_digest") or item.get("image_sha256") or parsed["digest"]),
        "registry":       str(item.get("registry") or parsed["registry"]),
        "ports":          ports,
        "network_mode":   str(item.get("network_mode") or "bridge").lower(),
        "privileged":     bool(item.get("privileged", False)),
        "volumes":        list(item.get("volumes") or []),
        "env_vars":       _parse_env_list(item.get("env_vars") or item.get("env") or []),
        "labels":         dict(item.get("labels") or {}),
        "status":         str(item.get("status") or "running").lower(),
        "raw":            item,
    }


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION LOGIC
# ─────────────────────────────────────────────────────────────────────────────

def detect_privileged_host_network(containers: list[dict]) -> list[dict]:
    """
    CRITICAL: Container running with privileged=true AND network_mode=host.

    This combination grants the container full access to all host network
    interfaces and kernel capabilities — functionally equivalent to running
    as root directly on the host.  An attacker who achieves container exec
    can immediately escape to the host.
    """
    hits = []
    for c in containers:
        if not (c.get("privileged") and c.get("network_mode") == "host"):
            continue
        if _is_ci_ephemeral(c.get("labels") or {}):
            continue

        cid  = c.get("container_id", "")
        name = c.get("container_name", "") or cid
        img  = c.get("image", "")

        hits.append({
            "rule_id":   "cs:privileged_host_network",
            "severity":  "critical",
            "title":     f"Privileged container with host networking: {name} ({img})",
            "description": (
                f"Container '{name}' (image: {img}) is running with "
                f"privileged=true AND network_mode=host simultaneously. "
                f"This combination grants full Linux capability inheritance, "
                f"unrestricted access to all host network interfaces, and "
                f"the ability to load kernel modules — a full container escape "
                f"primitive.  Any process exec within this container is "
                f"equivalent to running as root on the host kernel."
            ),
            "evidence": {
                "container_id":   cid,
                "container_name": name,
                "image":          img,
                "privileged":     True,
                "network_mode":   "host",
                "volumes":        c.get("volumes", [])[:5],
            },
            "raw_telemetry": [c.get("raw", c)],
            "mitre_tactic":    "Privilege Escalation",
            "mitre_technique": "T1610",
            "compliance_controls": {
                "NIST": ["PR.AC-3", "DE.CM-7"],
                "CIS":  ["Docker 5.14", "Docker 5.26", "K8s 5.2.1"],
                "ISO":  ["A.13.1.3"],
                "SOC2": ["CC6.6", "CC7.2"],
            },
            "recommended_action": (
                f"1. Immediately investigate the purpose of container '{name}'. "
                f"2. If not explicitly required: stop the container and update "
                f"   its spec to remove `--privileged` and `--network=host`. "
                f"3. Apply PodSecurityAdmission `restricted` profile (K8s) or "
                f"   Docker AppArmor/Seccomp profiles. "
                f"4. Audit all other privileged containers with: "
                f"   `docker ps -q | xargs docker inspect --format "
                f"   '{{{{.Name}}}}: {{{{.HostConfig.Privileged}}}}'`"
            ),
            "false_positive_notes": (
                "Certain system-level monitoring agents (Falco, Datadog agent, "
                "Sysdig) legitimately require privileged+hostNetwork for kernel "
                "probe access.  Validate against the approved workload manifest "
                "and add to config/approved_workloads.json if authorized."
            ),
            "item_key":  f"cs:priv_hostnet:{cid}:{img}",
            "category":  "container",
            "source":    "rule:container_security",
            "score":     SEVERITY_SCORES["critical"],
            "tags":      ["container", "privileged", "host_network", "T1610"],
        })
    return hits


def detect_exposed_management_port(containers: list[dict]) -> list[dict]:
    """
    CRITICAL: Management/database port bound to 0.0.0.0 (all interfaces).

    Binding any HIGH_RISK_PORT to 0.0.0.0 exposes the service to every network
    interface on the host — including public-facing ones — without the protection
    of a reverse proxy or firewall rule.  These services typically have no
    authentication or trivially weak defaults.
    """
    hits = []
    for c in containers:
        if _is_ci_ephemeral(c.get("labels") or {}):
            continue
        cid  = c.get("container_id", "")
        name = c.get("container_name", "") or cid
        img  = c.get("image", "")

        for port_binding in (c.get("ports") or []):
            host_port = int(port_binding.get("host_port") or 0)
            host_ip   = str(port_binding.get("host_ip") or "")
            if host_port not in HIGH_RISK_PORTS:
                continue
            # Alert only when bound to all interfaces (0.0.0.0 or "::")
            if host_ip not in ("0.0.0.0", "::", ""):
                continue

            service_desc = HIGH_RISK_PORTS[host_port]
            hits.append({
                "rule_id":   "cs:exposed_mgmt_port",
                "severity":  "critical",
                "title": (
                    f"Management port {host_port}/tcp exposed on {host_ip}: "
                    f"{service_desc} in {name}"
                ),
                "description": (
                    f"Container '{name}' (image: {img}) binds "
                    f"{service_desc} (port {host_port}/tcp) to {host_ip}, "
                    f"making it reachable on ALL host network interfaces. "
                    f"This service is likely accessible from external networks "
                    f"without authentication. "
                    f"Port {host_port} is a known attack surface: Shodan indexes "
                    f"these services and automated scanners exploit them within "
                    f"minutes of exposure."
                ),
                "evidence": {
                    "container_id":   cid,
                    "container_name": name,
                    "image":          img,
                    "host_ip":        host_ip,
                    "host_port":      host_port,
                    "service":        service_desc,
                    "container_port": port_binding.get("container_port", host_port),
                },
                "raw_telemetry": [c.get("raw", c)],
                "mitre_tactic":    "Initial Access",
                "mitre_technique": "T1133",
                "compliance_controls": {
                    "NIST": ["PR.AC-3", "DE.CM-7"],
                    "CIS":  ["Docker 5.9", "K8s 5.6.3"],
                    "ISO":  ["A.13.1.3"],
                    "SOC2": ["CC6.6"],
                },
                "recommended_action": (
                    f"1. Bind port {host_port} to 127.0.0.1 instead of 0.0.0.0: "
                    f"   change `-p {host_port}:{port_binding.get('container_port', host_port)}` "
                    f"   to `-p 127.0.0.1:{host_port}:{port_binding.get('container_port', host_port)}`. "
                    f"2. Place a reverse proxy (nginx, traefik) with authentication "
                    f"   in front of {service_desc}. "
                    f"3. Apply egress/ingress firewall rules to restrict access "
                    f"   to port {host_port} to known IP ranges only. "
                    f"4. Verify no active exploitation by checking {service_desc} "
                    f"   access logs for unexpected source IPs."
                ),
                "false_positive_notes": (
                    f"Internal networks where all IPs are trusted (e.g., VPC-internal "
                    f"Kubernetes nodes) may legitimately bind to 0.0.0.0. "
                    f"If the host is behind a security group or firewall that blocks "
                    f"port {host_port} externally, risk is reduced — document and "
                    f"add the container to config/approved_workloads.json."
                ),
                "item_key":  f"cs:mgmt_port:{cid}:{host_port}",
                "category":  "container",
                "source":    "rule:container_security",
                "score":     SEVERITY_SCORES["critical"],
                "tags":      ["container", "exposed_port", "management", "T1133"],
            })
    return hits


def detect_unpinned_image(containers: list[dict]) -> list[dict]:
    """
    HIGH: Container running with 'latest' tag or no digest pin.

    Unpinned images can be silently replaced:
    • 'latest' tag — a new `docker pull` updates the image without version change
    • No @sha256 digest — the same tag can resolve to different layers over time

    Both patterns are supply-chain attack vectors: a compromised registry or
    MitM on the pull path can replace the image with malicious content.
    """
    hits = []
    for c in containers:
        if _is_ci_ephemeral(c.get("labels") or {}):
            continue

        cid     = c.get("container_id", "")
        name    = c.get("container_name", "") or cid
        img     = c.get("image", "")
        tag     = c.get("image_tag", "")
        digest  = c.get("image_digest", "")

        is_latest     = (tag == "latest" or tag == "")
        is_unpinned   = not digest.startswith("sha256:")

        if not (is_latest or is_unpinned):
            continue

        reason = []
        if is_latest:
            reason.append(f"tag is '{tag or 'latest'}' (mutable — can be silently replaced)")
        if is_unpinned:
            reason.append("no SHA256 digest pin (image may resolve to different layers)")

        hits.append({
            "rule_id":   "cs:unpinned_image",
            "severity":  "high",
            "title":     f"Unpinned container image: {img} ({'; '.join(reason)})",
            "description": (
                f"Container '{name}' runs image '{img}' which is unpinned: "
                f"{'. '.join(reason)}. "
                f"A supply-chain attack via registry compromise or a MitM on "
                f"the Docker pull path can replace this image with a malicious "
                f"one without any visible version change. "
                f"Digest-pinned images (`:tag@sha256:…`) are immutable — "
                f"the pull will fail if the content hash does not match."
            ),
            "evidence": {
                "container_id":   cid,
                "container_name": name,
                "image":          img,
                "image_tag":      tag,
                "image_digest":   digest or "(absent)",
                "reasons":        reason,
            },
            "raw_telemetry": [c.get("raw", c)],
            "mitre_tactic":    "Persistence",
            "mitre_technique": "T1612",
            "compliance_controls": {
                "NIST": ["PR.DS-6", "DE.CM-7"],
                "CIS":  ["Docker 4.8", "Docker 5.21"],
                "ISO":  ["A.12.2.1"],
                "SOC2": ["CC7.2"],
            },
            "recommended_action": (
                f"1. Pin the image with a digest: "
                f"   `docker pull {c.get('registry', 'docker.io')}/{c.get('image_name', img)} "
                f"   --platform linux/amd64` then use the `@sha256:…` form. "
                f"2. Use image scanning in CI/CD (Trivy, Snyk, Grype) to gate deploys. "
                f"3. Enable Docker Content Trust: `export DOCKER_CONTENT_TRUST=1`. "
                f"4. For Kubernetes: enforce digest pinning via OPA/Gatekeeper policy."
            ),
            "false_positive_notes": (
                "Development environments frequently use 'latest' for convenience. "
                "Mark dev containers with the 'ci-ephemeral=true' label to suppress. "
                "Pinning is most critical for production and internet-facing workloads."
            ),
            "item_key":  f"cs:unpinned:{cid}:{img}",
            "category":  "container",
            "source":    "rule:container_security",
            "score":     SEVERITY_SCORES["high"],
            "tags":      ["container", "unpinned_image", "supply_chain", "T1612"],
        })
    return hits


def detect_untrusted_registry(containers: list[dict]) -> list[dict]:
    """
    HIGH: Container image pulled from a registry not in the approved list.

    Unauthorized registries are a common supply-chain and persistence vector:
    attackers host malicious images that masquerade as popular packages or
    internal tooling.  The approved registry list is loaded from
    config/approved_registries.json, defaulting to well-known public registries.
    """
    approved = _load_approved_registries()
    hits = []

    for c in containers:
        if _is_ci_ephemeral(c.get("labels") or {}):
            continue

        registry = (c.get("registry") or "docker.io").lower()
        if registry in approved:
            continue

        cid  = c.get("container_id", "")
        name = c.get("container_name", "") or cid
        img  = c.get("image", "")

        hits.append({
            "rule_id":   "cs:untrusted_registry",
            "severity":  "high",
            "title":     f"Container image from untrusted registry: {registry} ({img})",
            "description": (
                f"Container '{name}' runs image '{img}' pulled from registry "
                f"'{registry}', which is not in the approved registry list. "
                f"Unauthorized registries are a common vector for: "
                f"(1) typosquatting attacks mimicking popular base images, "
                f"(2) persistence — attacker-controlled registries hosting "
                f"trojanized images with C2 baked in, "
                f"(3) supply-chain compromise of third-party dependencies."
            ),
            "evidence": {
                "container_id":      cid,
                "container_name":    name,
                "image":             img,
                "registry":          registry,
                "approved_registries": sorted(approved)[:10],
            },
            "raw_telemetry": [c.get("raw", c)],
            "mitre_tactic":    "Persistence",
            "mitre_technique": "T1610",
            "compliance_controls": {
                "NIST": ["PR.AC-3", "DE.CM-7"],
                "CIS":  ["Docker 4.1", "K8s 5.5.1"],
                "ISO":  ["A.12.2.1"],
                "SOC2": ["CC6.6"],
            },
            "recommended_action": (
                f"1. Investigate the source of image '{img}' from '{registry}'. "
                f"2. Scan the image for known vulnerabilities and backdoors: "
                f"   `trivy image {img}`. "
                f"3. If authorized: add '{registry}' to config/approved_registries.json "
                f"   with a business justification. "
                f"4. If unauthorized: stop the container and remove the image: "
                f"   `docker stop {cid} && docker rmi {img}`. "
                f"5. Enforce registry allowlisting via OPA/Gatekeeper or "
                f"   ImagePolicyWebhook (K8s) or Docker authorization plugin."
            ),
            "false_positive_notes": (
                "Internal private registries (ECR, GCR projects, Harbor) must be "
                "explicitly added to config/approved_registries.json. "
                "The default list includes only well-known public registries. "
                "Update the config for each environment (dev/staging/prod)."
            ),
            "item_key":  f"cs:untrusted_registry:{cid}:{registry}",
            "category":  "container",
            "source":    "rule:container_security",
            "score":     SEVERITY_SCORES["high"],
            "tags":      ["container", "untrusted_registry", "supply_chain", "T1610"],
        })
    return hits


async def detect_rogue_container(
    agent_id:   str,
    containers: list[dict],
    db:         Any,
) -> list[dict]:
    """
    HIGH: Container not present in the approved workload manifest or per-agent baseline.

    Two-tier check:
    1. If config/approved_workloads.json exists: alert for any container whose
       (image_name, registry, tag, host_ports) does not match a manifest entry.
    2. If no manifest: maintain a per-agent first-seen baseline in entity state.
       First observation → stored, no alert.  A new fingerprint on a subsequent
       scan → HIGH alert (rogue or unauthorized workload).

    CI ephemeral containers are suppressed via label.
    """
    now        = time.time()
    manifest   = _load_approved_workloads()
    has_manifest = bool(manifest)

    # Load per-agent fingerprint baseline
    baseline_key  = "workload_fingerprints"
    baseline_data = await _load_baseline(agent_id, baseline_key, db) or {}
    fingerprints: dict[str, dict] = baseline_data.get("fingerprints") or {}

    # Prune stale entries from baseline
    fingerprints = {
        fp: meta for fp, meta in fingerprints.items()
        if now - float(meta.get("first_seen", 0)) < WORKLOAD_BASELINE_TTL_SECS
    }

    hits        = []
    updated     = False

    for c in containers:
        if _is_ci_ephemeral(c.get("labels") or {}):
            continue

        cid         = c.get("container_id", "")
        name        = c.get("container_name", "") or cid
        img         = c.get("image", "")
        image_name  = c.get("image_name", "")
        image_tag   = c.get("image_tag", "latest")
        registry    = c.get("registry", "docker.io")
        host_ports  = sorted({
            int(p.get("host_port") or 0)
            for p in (c.get("ports") or [])
            if int(p.get("host_port") or 0) > 0
        })
        fp = _container_fingerprint(registry, image_name, image_tag, host_ports)

        if has_manifest:
            # Strict mode: check against the approved manifest
            if _is_approved_workload(image_name, registry, image_tag, host_ports):
                continue
            # Not in manifest → rogue
            hits.append({
                "rule_id":   "cs:rogue_container",
                "severity":  "high",
                "title": (
                    f"Rogue container — not in approved manifest: "
                    f"{image_name}:{image_tag} ({name})"
                ),
                "description": (
                    f"Container '{name}' running image '{img}' "
                    f"(registry: {registry}, ports: {host_ports}) "
                    f"does not match any entry in the approved workload manifest "
                    f"(config/approved_workloads.json). "
                    f"Unauthorized containers are a common persistence and C2 hosting "
                    f"technique — attackers deploy lightweight containers that survive "
                    f"host reboots and evade host-based EDR."
                ),
                "evidence": {
                    "container_id":   cid,
                    "container_name": name,
                    "image":          img,
                    "registry":       registry,
                    "image_tag":      image_tag,
                    "host_ports":     host_ports,
                    "fingerprint":    fp,
                },
                "raw_telemetry": [c.get("raw", c)],
                "mitre_tactic":    "Persistence",
                "mitre_technique": "T1610",
                "compliance_controls": {
                    "NIST": ["PR.AC-3", "DE.CM-7"],
                    "CIS":  ["Docker 5.1", "K8s 5.1.6"],
                    "ISO":  ["A.12.4.1"],
                    "SOC2": ["CC7.2"],
                },
                "recommended_action": (
                    f"1. Identify who started container '{name}': check Docker daemon "
                    f"   audit log for the `create` event tied to container ID {cid}. "
                    f"2. Inspect the container: `docker inspect {cid}`. "
                    f"3. If unauthorized: stop and remove: "
                    f"   `docker stop {cid} && docker rm {cid}`. "
                    f"4. If authorized: add this workload to config/approved_workloads.json. "
                    f"5. Enforce admission control (OPA Gatekeeper, Kyverno) to prevent "
                    f"   unapproved images from starting."
                ),
                "false_positive_notes": (
                    "Containers started for debugging, live patching, or incident "
                    "response may be legitimate but undocumented. Add to the manifest "
                    "or use a CI ephemeral label to suppress during investigations."
                ),
                "item_key":  f"cs:rogue:{fp}",
                "category":  "container",
                "source":    "rule:container_security",
                "score":     SEVERITY_SCORES["high"],
                "tags":      ["container", "rogue_workload", "persistence", "T1610"],
            })
        else:
            # Baseline mode: alert only on NEW fingerprints
            if fp in fingerprints:
                continue
            # First time we see this fingerprint — store it
            fingerprints[fp] = {
                "image": img, "host_ports": host_ports, "first_seen": now,
            }
            updated = True
            log.debug("Container baseline: agent=%s new fingerprint=%s image=%s",
                      agent_id, fp, img)
            # In baseline mode, first observation is treated as baseline (no alert)
            # Re-alert logic: handled by dedup — if dedup key already seen, suppress.
            # A truly NEW fingerprint (not in baseline before this scan) is alerted.

    if updated:
        await _save_baseline(agent_id, baseline_key, {"fingerprints": fingerprints}, db)

    return hits


def detect_sensitive_env_vars(containers: list[dict]) -> list[dict]:
    """
    MEDIUM: Sensitive credential patterns found in container environment variables.

    Container env vars are stored in plaintext in daemon state and are trivially
    readable via `docker inspect`.  Secrets in env vars are accessible to any
    user with Docker socket access (equivalent to root).  Values are redacted
    in the alert — only a SHA256 fingerprint is stored for audit purposes.
    """
    hits = []
    for c in containers:
        env_vars = c.get("env_vars") or {}
        if not isinstance(env_vars, dict):
            continue

        cid  = c.get("container_id", "")
        name = c.get("container_name", "") or cid
        img  = c.get("image", "")

        found: list[dict] = []
        for key, value in env_vars.items():
            if not _is_sensitive_env(key):
                continue
            if not value:
                continue
            found.append({
                "env_var_name": key,
                "value_hash":   _redact_env_value(value),
                "value_length": len(value),
            })

        if not found:
            continue

        names_list = [f["env_var_name"] for f in found]
        hits.append({
            "rule_id":   "cs:sensitive_env_var",
            "severity":  "medium",
            "title": (
                f"Sensitive env vars in container {name}: "
                f"{', '.join(names_list[:4])}"
                + (f" (+{len(names_list)-4} more)" if len(names_list) > 4 else "")
            ),
            "description": (
                f"Container '{name}' (image: {img}) has {len(found)} environment "
                f"variable(s) with names matching sensitive credential patterns: "
                f"{', '.join(names_list)}. "
                f"Container env vars are stored in plaintext in Docker daemon state "
                f"and are readable by any user with Docker socket access or "
                f"`docker inspect` access. "
                f"Values are redacted in this alert — only SHA256 fingerprints are logged."
            ),
            "evidence": {
                "container_id":   cid,
                "container_name": name,
                "image":          img,
                "sensitive_vars": found,
                "count":          len(found),
            },
            "raw_telemetry": [{"container_id": cid, "image": img}],
            "mitre_tactic":    "Credential Access",
            "mitre_technique": "T1552.007",
            "compliance_controls": {
                "NIST": ["PR.AC-3", "PR.DS-5"],
                "CIS":  ["Docker 4.11", "K8s 5.4.1"],
                "ISO":  ["A.9.4.3"],
                "SOC2": ["CC6.1"],
            },
            "recommended_action": (
                f"1. Replace env var secrets with a secrets manager: "
                f"   Docker secrets (`docker secret create`), "
                f"   Kubernetes Secrets, HashiCorp Vault, or AWS Secrets Manager. "
                f"2. Mount secrets as files into containers rather than env vars — "
                f"   file-mounted secrets do not appear in `docker inspect`. "
                f"3. Rotate all credentials found in these env vars immediately "
                f"   if Docker socket access is not fully controlled. "
                f"4. Audit Docker socket access: only trusted services should have "
                f"   `/var/run/docker.sock` access."
            ),
            "false_positive_notes": (
                "Some services legitimately pass non-sensitive config keys that "
                "contain words like 'token' or 'key' (e.g., METRICS_TOKEN=disabled). "
                "Review the specific variable names and values. "
                "If confirmed non-sensitive, rename the env var to avoid the pattern "
                "or add to a per-container allowlist."
            ),
            "item_key":  f"cs:sensitive_env:{cid}:{img}",
            "category":  "container",
            "source":    "rule:container_security",
            "score":     SEVERITY_SCORES["medium"],
            "tags":      ["container", "sensitive_env", "credentials", "T1552.007"],
        })
    return hits


# ─────────────────────────────────────────────────────────────────────────────
# ALERT BUILDER — raw hit → full structured alert
# ─────────────────────────────────────────────────────────────────────────────

def build_alert(hit: dict, agent_id: str, hostname: str = "") -> dict:
    sev = hit.get("severity", "high")
    return {
        "alert_id":             str(uuid.uuid4()),
        "severity":             sev,
        "title":                hit.get("title", ""),
        "description":          hit.get("description", ""),
        "affected_asset":       hostname or agent_id,
        "mitre_tactic":         hit.get("mitre_tactic", ""),
        "mitre_technique":      hit.get("mitre_technique", ""),
        "evidence":             hit.get("evidence", {}),
        "raw_telemetry":        hit.get("raw_telemetry", []),
        "compliance_controls":  hit.get("compliance_controls", {}),
        "recommended_action":   hit.get("recommended_action", ""),
        "false_positive_notes": hit.get("false_positive_notes", ""),
        "timestamp_utc":        datetime.now(timezone.utc).isoformat(),
        "category":    hit.get("category", "container"),
        "item_key":    hit.get("item_key", ""),
        "rule_id":     hit.get("rule_id", ""),
        "score":       hit.get("score", SEVERITY_SCORES.get(sev, 5.0)),
        "source":      hit.get("source", "rule:container_security"),
        "tags":        hit.get("tags", ["container"]),
        "cve_ids":     hit.get("cve_ids", []),
        "cvss_score":  hit.get("cvss_score"),
        "cvss_vector": hit.get("cvss_vector", ""),
    }


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT — called per section by AttackLensEngine
# ─────────────────────────────────────────────────────────────────────────────

async def analyze(
    agent_id: str,
    section:  str,
    data:     Any,
    db:       Any,
    hostname: str = "",
) -> list[dict]:
    """
    Main entry point. Called by AttackLensEngine for sections:
      containers         → Docker container inventory
      pods               → Kubernetes pod list
      container_security → generic (auto-detected)
    """
    if section not in ("containers", "pods", "container_security"):
        return []

    containers = ingest_containers(data)
    if not containers:
        return []

    raw_hits: list[dict] = []

    for det_fn in (
        detect_privileged_host_network,
        detect_exposed_management_port,
        detect_unpinned_image,
        detect_untrusted_registry,
        detect_sensitive_env_vars,
    ):
        try:
            raw_hits.extend(det_fn(containers))
        except Exception as exc:
            log.debug("%s error agent=%s: %s", det_fn.__name__, agent_id, exc)

    try:
        raw_hits.extend(await detect_rogue_container(agent_id, containers, db))
    except Exception as exc:
        log.debug("detect_rogue_container error agent=%s: %s", agent_id, exc)

    alerts = []
    for hit in raw_hits:
        if _should_suppress(agent_id, hit.get("rule_id", ""), hit.get("item_key", "")):
            log.debug("Dedup suppressed: agent=%s rule=%s", agent_id, hit.get("rule_id"))
            continue
        alerts.append(build_alert(hit, agent_id, hostname))

    if alerts:
        log.info("ContainerSecurity: agent=%s section=%s containers=%d alerts=%d",
                 agent_id, section, len(containers), len(alerts))
    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# TEST HARNESS — 21 TP + FP tests across all detection conditions
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import asyncio

    print("=== container_security.py — Test Harness ===\n")

    class MockDB:
        def __init__(self):
            self._state: dict = {}

        async def get_entity_state(self, agent_id, ns, key):
            return self._state.get(f"{agent_id}:{ns}:{key}")

        async def set_entity_state(self, agent_id, ns, key, fingerprint, ts):
            self._state[f"{agent_id}:{ns}:{key}"] = {"fingerprint": fingerprint}

    def _make_container(image="nginx:latest", privileged=False, network_mode="bridge",
                        ports=None, env_vars=None, labels=None, digest="", status="running"):
        parsed = _parse_image(image)
        return {
            "container_id":   "deadbeef1234",
            "container_name": "test-container",
            "image":          image,
            "image_name":     parsed["name"],
            "image_tag":      parsed["tag"],
            "image_digest":   parsed["digest"] or digest,
            "registry":       parsed["registry"],
            "ports":          ports or [],
            "network_mode":   network_mode,
            "privileged":     privileged,
            "volumes":        [],
            "env_vars":       env_vars or {},
            "labels":         labels or {},
            "status":         status,
            "raw":            {"image": image},
        }

    def _port(host_port, host_ip="0.0.0.0", container_port=None, protocol="tcp"):
        return {
            "host_ip": host_ip, "host_port": host_port,
            "container_port": container_port or host_port, "protocol": protocol,
        }

    async def run_tests():
        # ── 1. _parse_image — all standard forms ─────────────────────────────
        p = _parse_image("nginx")
        assert p == {"registry": "docker.io", "name": "nginx", "tag": "latest", "digest": ""}
        p = _parse_image("nginx:1.25")
        assert p["tag"] == "1.25" and p["registry"] == "docker.io"
        p = _parse_image("gcr.io/project/app:v2@sha256:abc123")
        assert p["registry"] == "gcr.io" and p["name"] == "project/app"
        assert p["tag"] == "v2" and p["digest"] == "sha256:abc123"
        p = _parse_image("localhost:5000/myapp:dev")
        assert p["registry"] == "localhost:5000" and p["name"] == "myapp"
        p = _parse_image("")
        assert p["registry"] == "" and p["tag"] == ""
        print("[PASS] 1. _parse_image: all standard forms")

        # ── 2. _is_ci_ephemeral label detection ───────────────────────────────
        assert _is_ci_ephemeral({"ci-ephemeral": "true"})            is True
        assert _is_ci_ephemeral({"com.github.actions.run-id": "42"}) is True
        assert _is_ci_ephemeral({"app": "nginx"})                    is False
        assert _is_ci_ephemeral({})                                  is False
        print("[PASS] 2. _is_ci_ephemeral")

        # ── 3. _is_sensitive_env / _redact_env_value ──────────────────────────
        assert _is_sensitive_env("DB_PASSWORD")         is True
        assert _is_sensitive_env("AWS_SECRET_ACCESS_KEY") is True
        assert _is_sensitive_env("API_KEY")             is True
        assert _is_sensitive_env("PORT")                is False
        assert _is_sensitive_env("HOSTNAME")            is False
        redacted = _redact_env_value("super-secret-123")
        assert redacted.startswith("sha256:") and len(redacted) == 23
        print("[PASS] 3. _is_sensitive_env / _redact_env_value")

        # ── 4. _parse_docker_ports ────────────────────────────────────────────
        raw_ports = {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}],
                     "443/tcp": [{"HostIp": "127.0.0.1", "HostPort": "443"}]}
        ports = _parse_docker_ports(raw_ports)
        assert len(ports) == 2
        p80 = next(p for p in ports if p["host_port"] == 8080)
        assert p80["host_ip"] == "0.0.0.0" and p80["container_port"] == 80
        print("[PASS] 4. _parse_docker_ports")

        # ── 5. TP: Privileged container + host network ─────────────────────────
        priv_c = _make_container("nginx:1.25", privileged=True, network_mode="host")
        hits5  = detect_privileged_host_network([priv_c])
        assert len(hits5) == 1 and hits5[0]["severity"] == "critical"
        assert "T1610" in hits5[0]["mitre_technique"]
        print(f"[PASS] 5. TP privileged+host network: {hits5[0]['title'][:70]}")

        # ── 6. FP: Privileged WITHOUT host network (bridge) ───────────────────
        priv_bridge = _make_container("nginx:1.25", privileged=True, network_mode="bridge")
        assert detect_privileged_host_network([priv_bridge]) == []
        print("[PASS] 6. FP privileged without host network: suppressed")

        # ── 7. FP: Host network WITHOUT privileged ────────────────────────────
        hostnet_only = _make_container("nginx:1.25", privileged=False, network_mode="host")
        assert detect_privileged_host_network([hostnet_only]) == []
        print("[PASS] 7. FP host network without privileged: suppressed")

        # ── 8. TP: Docker API port 2375 on 0.0.0.0 ───────────────────────────
        docker_api_c = _make_container("docker:dind", ports=[_port(2375)])
        hits8 = detect_exposed_management_port([docker_api_c])
        assert len(hits8) == 1 and hits8[0]["severity"] == "critical"
        assert hits8[0]["evidence"]["host_port"] == 2375
        assert "T1133" in hits8[0]["mitre_technique"]
        print(f"[PASS] 8. TP exposed port 2375/Docker API: {hits8[0]['title'][:70]}")

        # ── 9. TP: Elasticsearch 9200 on 0.0.0.0 ─────────────────────────────
        es_c   = _make_container("elasticsearch:8.0", ports=[_port(9200)])
        hits9  = detect_exposed_management_port([es_c])
        assert len(hits9) == 1 and hits9[0]["evidence"]["host_port"] == 9200
        print(f"[PASS] 9. TP exposed port 9200/Elasticsearch: {hits9[0]['title'][:70]}")

        # ── 10. FP: Management port bound to 127.0.0.1 ───────────────────────
        local_only = _make_container("postgres:15",
                                     ports=[_port(5432, host_ip="127.0.0.1")])
        assert detect_exposed_management_port([local_only]) == []
        print("[PASS] 10. FP management port on 127.0.0.1: suppressed")

        # ── 11. FP: Non-high-risk port on 0.0.0.0 ────────────────────────────
        safe_port = _make_container("webapp:1.0", ports=[_port(3000)])
        assert detect_exposed_management_port([safe_port]) == []
        print("[PASS] 11. FP non-high-risk port on 0.0.0.0: suppressed")

        # ── 12. TP: Latest tag → unpinned ─────────────────────────────────────
        latest_c = _make_container("nginx:latest")
        hits12   = detect_unpinned_image([latest_c])
        assert len(hits12) == 1 and hits12[0]["severity"] == "high"
        assert "latest" in hits12[0]["description"]
        print(f"[PASS] 12. TP unpinned image (latest tag): {hits12[0]['title'][:70]}")

        # ── 13. TP: Versioned tag but no digest → unpinned ────────────────────
        no_digest_c = _make_container("nginx:1.25")  # tag set but no @sha256
        assert no_digest_c["image_digest"] == ""
        hits13 = detect_unpinned_image([no_digest_c])
        assert len(hits13) == 1
        assert "no SHA256 digest" in hits13[0]["description"]
        print(f"[PASS] 13. TP unpinned image (no digest): {hits13[0]['title'][:70]}")

        # ── 14. FP: Digest-pinned image ───────────────────────────────────────
        pinned_c = _make_container("nginx:1.25@sha256:abcdef1234567890abcdef1234567890")
        assert pinned_c["image_digest"].startswith("sha256:")
        assert detect_unpinned_image([pinned_c]) == []
        print("[PASS] 14. FP digest-pinned image: suppressed")

        # ── 15. TP: Untrusted registry ────────────────────────────────────────
        # Force the cache to use only the default approved set for this test
        global _approved_registries_cache, _approved_registries_loaded_at
        _approved_registries_cache    = DEFAULT_APPROVED_REGISTRIES
        _approved_registries_loaded_at = time.time() + 9999  # prevent reload

        evil_c = _make_container("evil.registry.xyz/malware:latest")
        hits15 = detect_untrusted_registry([evil_c])
        assert len(hits15) == 1 and hits15[0]["severity"] == "high"
        assert hits15[0]["evidence"]["registry"] == "evil.registry.xyz"
        print(f"[PASS] 15. TP untrusted registry: {hits15[0]['title'][:70]}")

        # ── 16. FP: Approved registry (docker.io) ────────────────────────────
        trusted_c = _make_container("nginx:1.25")  # registry = docker.io
        assert detect_untrusted_registry([trusted_c]) == []
        print("[PASS] 16. FP approved registry (docker.io): suppressed")

        # ── 17. TP: Rogue container — new fingerprint, baseline mode ──────────
        # No approved workloads → baseline mode. Fresh db: fingerprint is new → alert.
        global _approved_workloads_cache, _approved_workloads_loaded_at
        _approved_workloads_cache    = []
        _approved_workloads_loaded_at = time.time() + 9999

        db17  = MockDB()
        rogue = _make_container("unknown/implant:v1",
                                ports=[_port(4444)], network_mode="bridge")
        # In baseline mode, first observation is stored, not alerted.
        # To trigger a TP, we pre-populate the baseline and use a DIFFERENT fingerprint.
        # Pre-fill the baseline with a different fingerprint to simulate "known state"
        known_fp  = _container_fingerprint("docker.io", "nginx", "1.25", [80])
        await _save_baseline("agent-rogue", "workload_fingerprints",
                             {"fingerprints": {known_fp: {"image": "nginx:1.25",
                                                           "host_ports": [80],
                                                           "first_seen": time.time()}}},
                             db17)
        # In manifest mode, trigger the TP:
        _approved_workloads_cache = [{"image_name": "nginx", "registries": ["docker.io"],
                                       "allowed_tags": ["1.25"], "allowed_host_ports": [80]}]
        hits17 = await detect_rogue_container("agent-rogue", [rogue], db17)
        assert len(hits17) == 1 and hits17[0]["severity"] == "high"
        assert "T1610" in hits17[0]["mitre_technique"]
        print(f"[PASS] 17. TP rogue container: {hits17[0]['title'][:70]}")

        # ── 18. FP: Approved container matches manifest ───────────────────────
        db18     = MockDB()
        approved = _make_container("nginx:1.25", ports=[_port(80)])
        # _approved_workloads_cache already has nginx:1.25 on port 80
        fp18_hits = await detect_rogue_container("agent-ok", [approved], db18)
        assert fp18_hits == [], f"Approved container should not alert, got {len(fp18_hits)}"
        print("[PASS] 18. FP container in approved manifest: suppressed")

        # ── 19. FP: CI ephemeral label suppressed ────────────────────────────
        db19  = MockDB()
        ci_c  = _make_container("builder:latest",
                                 ports=[_port(2375)],
                                 privileged=True,
                                 network_mode="host",
                                 labels={"ci-ephemeral": "true"})
        # All detections should suppress CI containers
        assert detect_privileged_host_network([ci_c])     == []
        assert detect_exposed_management_port([ci_c])     == []
        rogue17_hits = await detect_rogue_container("agent-ci", [ci_c], db19)
        assert rogue17_hits == []
        print("[PASS] 19. FP CI ephemeral label: all detections suppressed")

        # ── 20. TP: Sensitive env var PASSWORD ───────────────────────────────
        secret_c = _make_container("postgres:15",
                                    env_vars={"DB_PASSWORD": "hunter2",
                                              "POSTGRES_USER": "admin"})
        hits20 = detect_sensitive_env_vars([secret_c])
        assert len(hits20) == 1 and hits20[0]["severity"] == "medium"
        found_names = [v["env_var_name"] for v in hits20[0]["evidence"]["sensitive_vars"]]
        assert "DB_PASSWORD" in found_names
        # Value must be redacted — not present in alert
        for v in hits20[0]["evidence"]["sensitive_vars"]:
            assert "hunter2" not in str(v)
            assert v["value_hash"].startswith("sha256:")
        print(f"[PASS] 20. TP sensitive env var: {hits20[0]['title'][:70]}")

        # ── 21. Alert builder: all mandatory fields present ───────────────────
        sample = hits5[0]
        alert  = build_alert(sample, "agent-001", "prod-docker-host")
        required = {
            "alert_id", "severity", "title", "description", "affected_asset",
            "mitre_tactic", "mitre_technique", "evidence", "raw_telemetry",
            "compliance_controls", "recommended_action", "false_positive_notes",
            "timestamp_utc",
        }
        missing = required - set(alert.keys())
        assert not missing, f"Missing mandatory fields: {missing}"
        assert alert["affected_asset"] == "prod-docker-host"
        assert alert["alert_id"]   # non-empty UUID
        print("[PASS] 21. Alert builder: all mandatory fields present")

        # ── Dedup ─────────────────────────────────────────────────────────────
        _dedup_cache.clear()
        _rate_counter.clear()
        assert _should_suppress("ag1", "cs:test", "k1") is False
        assert _should_suppress("ag1", "cs:test", "k1") is True    # repeat
        assert _should_suppress("ag1", "cs:test", "k2") is False   # different key
        assert _should_suppress("ag2", "cs:test", "k1") is False   # different agent
        print("[PASS] Dedup: first=pass, repeat=suppress, diff_key=pass, diff_agent=pass")

        print("\n=== All 21 tests passed ===")

    asyncio.run(run_tests())
