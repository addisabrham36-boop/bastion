"""
Validated runtime and environment settings for Bastion-TIP using Pydantic Settings.
"""

from pathlib import Path
from typing import List, Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # General Environment
    bastion_env: str = Field(default="development", alias="BASTION_ENV")
    bastion_log_level: str = Field(default="INFO", alias="BASTION_LOG_LEVEL")
    bastion_listen_host: str = Field(default="127.0.0.1", alias="BASTION_LISTEN_HOST")
    bastion_listen_port: int = Field(default=9000, alias="BASTION_LISTEN_PORT")
    bastion_public_base_url: str = Field(default="http://127.0.0.1:9000", alias="BASTION_PUBLIC_BASE_URL")

    # Policy & Configuration Files
    bastion_site_config: Path = Field(default=Path("bastion/config/sites.yaml"), alias="BASTION_SITE_CONFIG")
    bastion_rule_config: Path = Field(default=Path("bastion/config/rules.yaml"), alias="BASTION_RULE_CONFIG")
    bastion_default_mode: str = Field(default="detection", alias="BASTION_DEFAULT_MODE")  # "detection" | "prevention"

    # Preflight Request Limits (bytes & seconds)
    bastion_max_body_bytes: int = Field(default=1_048_576, alias="BASTION_MAX_BODY_BYTES")      # 1 MB
    bastion_max_path_bytes: int = Field(default=8_192, alias="BASTION_MAX_PATH_BYTES")          # 8 KB
    bastion_max_header_bytes: int = Field(default=32_768, alias="BASTION_MAX_HEADER_BYTES")     # 32 KB
    bastion_upstream_timeout_seconds: float = Field(default=15.0, alias="BASTION_UPSTREAM_TIMEOUT_SECONDS")

    # Proxy Trust Boundaries
    bastion_trusted_proxy_cidrs: str = Field(default="127.0.0.1/32,::1/128", alias="BASTION_TRUSTED_PROXY_CIDRS")

    # Redis Backend (IOCs, Rate Limiting, Event Streams)
    redis_url: str = Field(default="redis://127.0.0.1:6379/0", alias="REDIS_URL")
    redis_event_stream: str = Field(default="bastion:events:v1", alias="REDIS_EVENT_STREAM")
    bastion_rate_limit_enabled: bool = Field(default=True, alias="BASTION_RATE_LIMIT_ENABLED")
    bastion_rate_limit_timeout_seconds: float = Field(default=0.1, alias="BASTION_RATE_LIMIT_TIMEOUT_SECONDS")
    bastion_ioc_timeout_seconds: float = Field(default=0.1, alias="BASTION_IOC_TIMEOUT_SECONDS")

    # OpenSearch Backend (Telemetry)
    opensearch_url: str = Field(default="http://127.0.0.1:9200", alias="OPENSEARCH_URL")
    opensearch_username: Optional[str] = Field(default="admin", alias="OPENSEARCH_USERNAME")
    opensearch_password: Optional[str] = Field(default=None, alias="OPENSEARCH_PASSWORD")
    opensearch_verify_tls: bool = Field(default=False, alias="OPENSEARCH_VERIFY_TLS")

    # Auth & Administration
    bastion_session_secret: str = Field(default="insecure-dev-secret-change-in-production", alias="BASTION_SESSION_SECRET")
    bastion_admin_networks: str = Field(default="127.0.0.1/32,::1/128", alias="BASTION_ADMIN_NETWORKS")

    @field_validator("bastion_default_mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        mode = v.lower()
        if mode not in ("detection", "prevention"):
            raise ValueError(f"Invalid mode '{v}'. Must be 'detection' or 'prevention'.")
        return mode

    @property
    def trusted_proxies_list(self) -> List[str]:
        return [cidr.strip() for cidr in self.bastion_trusted_proxy_cidrs.split(",") if cidr.strip()]

    @property
    def admin_networks_list(self) -> List[str]:
        return [cidr.strip() for cidr in self.bastion_admin_networks.split(",") if cidr.strip()]


_settings_instance: Optional[Settings] = None


def get_settings() -> Settings:
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings()
    return _settings_instance


def reset_settings():
    global _settings_instance
    _settings_instance = None
