"""
Site configuration models and hostname-to-site resolution.
Strictly disallows dynamic or arbitrary upstream URLs.
"""

from pathlib import Path
from typing import Dict, List, Optional
import yaml
from pydantic import BaseModel, Field, field_validator


class RateLimitConfig(BaseModel):
    enabled: bool = True
    requests: int = Field(default=60, ge=1, le=100_000)
    window_seconds: int = Field(default=60, ge=1, le=86_400)


class ScoreThresholds(BaseModel):
    log: int = Field(default=20, ge=0)
    block: int = Field(default=50, ge=0)


class SiteConfig(BaseModel):
    id: str
    hostnames: List[str]
    upstream_origin: str
    verify_upstream_tls: bool = True
    mode: str = "detection"  # "detection" | "prevention"
    allowed_methods: List[str] = [
        "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
    ]
    max_body_bytes: int = 1_048_576
    max_path_bytes: int = 8_192
    rule_profile: str = "default"
    score_thresholds: ScoreThresholds = Field(default_factory=ScoreThresholds)
    rate_limits: Dict[str, RateLimitConfig] = Field(default_factory=dict)
    unsupported_body_policy: str = "allow_and_log"

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        mode = v.lower()
        if mode not in ("detection", "prevention"):
            raise ValueError(f"Site mode must be 'detection' or 'prevention', got '{v}'")
        return mode

    @field_validator("upstream_origin")
    @classmethod
    def validate_upstream(cls, v: str) -> str:
        v_clean = v.strip().rstrip("/")
        if not (v_clean.startswith("http://") or v_clean.startswith("https://")):
            raise ValueError(f"Upstream origin must begin with http:// or https://: '{v}'")
        return v_clean


class SiteRepository:
    """In-memory loaded site registry mapped strictly by hostname."""

    def __init__(self, sites: List[SiteConfig]):
        self._sites_by_id: Dict[str, SiteConfig] = {}
        self._sites_by_host: Dict[str, SiteConfig] = {}
        for site in sites:
            self._sites_by_id[site.id] = site
            for host in site.hostnames:
                clean_host = host.lower().strip()
                self._sites_by_host[clean_host] = site

    @classmethod
    def load_from_yaml(cls, path: Path | str) -> "SiteRepository":
        path = Path(path)
        if not path.exists():
            return cls([])
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        raw_sites = raw.get("sites", [])
        parsed_sites = [SiteConfig(**s) for s in raw_sites]
        return cls(parsed_sites)

    def resolve_site(self, host: str) -> Optional[SiteConfig]:
        """Resolve incoming Host header (stripping optional port) to configured site."""
        if not host:
            return None
        clean_host = host.lower().strip()
        host_without_port = clean_host.split(":")[0]
        # Match exact host:port or hostname alone
        return self._sites_by_host.get(clean_host) or self._sites_by_host.get(host_without_port)

    def get_site(self, site_id: str) -> Optional[SiteConfig]:
        return self._sites_by_id.get(site_id)

    def list_sites(self) -> List[SiteConfig]:
        return list(self._sites_by_id.values())
