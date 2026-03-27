"""
agent/agent/config.py — Validated config models for agent.toml.

Fail-fast at startup: if agent.toml is malformed or missing required
fields, the agent prints a clear error and exits rather than silently
failing later.

Usage in core.py:
    from .config import AgentConfig
    cfg = AgentConfig.from_toml("agent.toml")
    raw = cfg.to_dict()   # backward-compatible raw dict for legacy code
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        print("ERROR: Python 3.11+ required, or: pip install tomli", file=sys.stderr)
        sys.exit(1)


# ── Sub-models ────────────────────────────────────────────────────────────────

@dataclass
class AgentIdentity:
    id: str
    name: str = "Unknown Mac"
    description: str = ""

    def __post_init__(self) -> None:
        slug = self.id.replace("-", "").replace("_", "")
        if not self.id or not slug.isalnum():
            raise ValueError(
                f"[agent] id must be alphanumeric with hyphens/underscores, "
                f"got: {self.id!r}"
            )


@dataclass
class ManagerConnectionConfig:
    url: str
    api_key: str
    tls_verify: bool = True
    timeout_sec: int = 30
    retry_attempts: int = 3
    retry_delay_sec: int = 5
    max_queue_size: int = 500

    def __post_init__(self) -> None:
        if not self.url.startswith("https://"):
            raise ValueError(
                f"[manager] url must start with https://, got: {self.url!r}"
            )
        if not self.api_key or len(self.api_key) < 32:
            raise ValueError(
                "[manager] api_key must be ≥32 chars. "
                "Generate one: python3 scripts/keygen.py"
            )
        if self.api_key.upper().startswith("REPLACE"):
            raise ValueError(
                "[manager] api_key is still the placeholder value. "
                "Generate a real key: python3 scripts/keygen.py"
            )
        if not self.tls_verify:
            import logging
            logging.getLogger("agent.config").warning(
                "TLS verification disabled (tls_verify = false) — "
                "use only with self-signed certs in development"
            )


@dataclass
class SectionConfig:
    enabled: bool = True
    interval_sec: int = 60
    send: bool = True


@dataclass
class CollectionConfig:
    enabled: bool = True
    tick_sec: int = 5
    sections: dict[str, SectionConfig] = field(default_factory=dict)


@dataclass
class LoggingConfig:
    level: str = "INFO"
    file: str = "logs/agent.log"
    max_mb: int = 10
    backups: int = 3

    _VALID_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

    def __post_init__(self) -> None:
        self.level = self.level.upper()
        if self.level not in self._VALID_LEVELS:
            raise ValueError(
                f"[logging] level must be one of {self._VALID_LEVELS}, "
                f"got: {self.level!r}"
            )


# ── Root config ───────────────────────────────────────────────────────────────

@dataclass
class AgentConfig:
    agent: AgentIdentity
    manager: ManagerConnectionConfig
    collection: CollectionConfig
    logging: LoggingConfig

    @classmethod
    def from_toml(cls, path: str) -> "AgentConfig":
        """Load and validate config from a TOML file. Raises on any error."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(
                f"Config file not found: {path}\n"
                f"  Copy the example: cp agent.toml.example agent.toml"
            )
        with open(p, "rb") as f:
            raw = tomllib.load(f)

        try:
            agent_cfg  = AgentIdentity(**raw.get("agent", {}))
            mgr_cfg    = ManagerConnectionConfig(**raw.get("manager", {}))
            coll_cfg   = _parse_collection(raw.get("collection", {}))
            log_cfg    = LoggingConfig(**raw.get("logging", {}))
        except TypeError as exc:
            raise ValueError(f"Config error in {path}: {exc}") from exc

        return cls(
            agent=agent_cfg,
            manager=mgr_cfg,
            collection=coll_cfg,
            logging=log_cfg,
        )

    def to_dict(self) -> dict:
        """Return a raw dict compatible with the legacy config consumers."""
        sections = {
            name: {
                "enabled":      s.enabled,
                "interval_sec": s.interval_sec,
                "send":         s.send,
            }
            for name, s in self.collection.sections.items()
        }
        return {
            "agent": {
                "id":          self.agent.id,
                "name":        self.agent.name,
                "description": self.agent.description,
            },
            "manager": {
                "url":             self.manager.url,
                "api_key":         self.manager.api_key,
                "tls_verify":      self.manager.tls_verify,
                "timeout_sec":     self.manager.timeout_sec,
                "retry_attempts":  self.manager.retry_attempts,
                "retry_delay_sec": self.manager.retry_delay_sec,
                "max_queue_size":  self.manager.max_queue_size,
            },
            "collection": {
                "enabled":  self.collection.enabled,
                "tick_sec": self.collection.tick_sec,
                "sections": sections,
            },
            "logging": {
                "level":   self.logging.level,
                "file":    self.logging.file,
                "max_mb":  self.logging.max_mb,
                "backups": self.logging.backups,
            },
        }


# ── Internal ──────────────────────────────────────────────────────────────────

def _parse_collection(raw: dict) -> CollectionConfig:
    sections_raw = dict(raw)
    sections_raw.pop("enabled",  None)
    sections_raw.pop("tick_sec", None)
    sections_per_name = sections_raw.pop("sections", {})

    sections = {
        name: SectionConfig(**cfg)
        for name, cfg in sections_per_name.items()
    }
    return CollectionConfig(
        enabled=raw.get("enabled", True),
        tick_sec=raw.get("tick_sec", 5),
        sections=sections,
    )
