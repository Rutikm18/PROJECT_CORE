"""
manager/manager/config.py — Manager runtime configuration from environment.

All secrets come from environment variables — never from config files or code.
Fail-fast at startup: missing or invalid settings raise immediately.

Usage:
    from .config import ManagerSettings
    settings = ManagerSettings.from_env()
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TLSConfig:
    cert_file: str
    key_file: str

    def __post_init__(self) -> None:
        for attr, path in [("cert_file", self.cert_file), ("key_file", self.key_file)]:
            if not Path(path).exists():
                raise FileNotFoundError(
                    f"TLS {attr} not found: {path}\n"
                    f"  Generate certs: bash scripts/setup.sh certs"
                )


@dataclass
class ManagerSettings:
    api_key: str
    db_path: str
    bind_host: str = "0.0.0.0"
    bind_port: int = 8443
    tls: TLSConfig | None = None

    # Security
    replay_window_sec: int = 300          # ±5 minutes
    max_payload_bytes: int = 10_485_760   # 10 MiB hard cap on ingest body

    # CORS — restrict to specific origins in production
    cors_origins: list[str] = field(default_factory=lambda: ["*"])

    def __post_init__(self) -> None:
        if not self.api_key or len(self.api_key) < 32:
            raise ValueError(
                "API_KEY environment variable is required and must be ≥32 chars.\n"
                "  Generate: python3 scripts/keygen.py"
            )
        if self.cors_origins == ["*"]:
            import logging
            logging.getLogger("manager.config").warning(
                "CORS_ORIGINS=* — all origins allowed. "
                "Set CORS_ORIGINS to specific domains in production."
            )

    @classmethod
    def from_env(cls) -> "ManagerSettings":
        """Load all settings from environment variables with safe defaults."""
        api_key   = os.environ.get("API_KEY", "")
        db_path   = os.environ.get("DB_PATH", _default_db_path())
        bind_host = os.environ.get("BIND_HOST", "0.0.0.0")
        bind_port = int(os.environ.get("BIND_PORT", "8443"))

        # TLS is optional — can be offloaded to a reverse proxy (nginx, Caddy)
        cert = os.environ.get("TLS_CERT", "")
        key  = os.environ.get("TLS_KEY",  "")
        tls  = TLSConfig(cert, key) if (cert and key) else None

        cors_raw     = os.environ.get("CORS_ORIGINS", "*")
        cors_origins = [o.strip() for o in cors_raw.split(",") if o.strip()]

        return cls(
            api_key=api_key,
            db_path=db_path,
            bind_host=bind_host,
            bind_port=bind_port,
            tls=tls,
            cors_origins=cors_origins,
        )


def _default_db_path() -> str:
    here = Path(__file__).parent.parent   # manager/ package root
    return str(here / "data" / "manager.db")
