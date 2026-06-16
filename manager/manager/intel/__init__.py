"""
manager/manager/intel — Multi-source threat intelligence pipeline.

Architecture:
  sources.py   — Source adapters with CircuitBreaker per source
  pipeline.py  — IntelPipeline: parallel fetch + merge + graceful degradation
  validator.py — Cross-source validation, schema checks, confidence scoring
  scorer.py    — Enhanced composite scorer (CVSS + EPSS + KEV + exploits + PoC)

Sources (free, no mandatory API keys):
  NVD          — NIST CVE database (existing CVELookup, rate-gated)
  CISA KEV     — Known Exploited Vulnerabilities (existing FeedManager)
  EPSS         — FIRST.org exploit probability (existing FeedManager)
  ExploitDB    — Offline CSV download (GitLab mirror, weekly)
  Metasploit   — CVE→module mapping JSON (GitHub, weekly)
  PoC-GitHub   — poc-in-github.motikan2010.net API (on-demand)
  OSV          — Google Open Source Vulnerabilities (on-demand)
  GHSA         — GitHub Security Advisories (on-demand, optional token)
  CIRCL        — cve.circl.lu NVD mirror (NVD fallback, on-demand)
"""

from .pipeline import IntelPipeline

__all__ = ["IntelPipeline"]
