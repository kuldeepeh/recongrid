"""Application settings, loaded from environment variables."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # ─── Auth ──────────────────────────────────────────────
    admin_password: str = "change-me-please"
    secret_key: str = "change-me-to-a-long-random-string"
    session_expire_minutes: int = 720

    # ─── Database ──────────────────────────────────────────
    postgres_user: str = "recongrid"
    postgres_password: str = "recongrid"
    postgres_db: str = "recongrid"
    postgres_host: str = "postgres"
    postgres_port: int = 5432

    # ─── Redis ─────────────────────────────────────────────
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_broker_db: int = 0
    redis_result_db: int = 1
    redis_cache_db: int = 2

    # ─── Scan sandbox ──────────────────────────────────────
    # "sandbox" -> exec into the isolated container; "local" -> run in-process (dev).
    tool_execution_mode: str = "sandbox"
    sandbox_container_name: str = "recongrid-scan-sandbox"
    tool_stage_timeout: int = 1800
    scandata_dir: str = "/scandata"

    # ─── nmap enrichment ───────────────────────────────────
    nmap_enabled: bool = True
    nmap_os_detect: bool = True          # -O (needs NET_RAW capability)
    nmap_timing: str = "T4"              # nmap timing template
    nmap_timeout: int = 900              # seconds ceiling for the enrichment pass

    # ─── Retention ─────────────────────────────────────────
    temp_project_ttl_days: int = 7
    raw_output_keep_runs: int = 20

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+psycopg2://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    def redis_url(self, db: int) -> str:
        return f"redis://{self.redis_host}:{self.redis_port}/{db}"

    @property
    def broker_url(self) -> str:
        return self.redis_url(self.redis_broker_db)

    @property
    def result_backend(self) -> str:
        return self.redis_url(self.redis_result_db)

    @property
    def cache_url(self) -> str:
        return self.redis_url(self.redis_cache_db)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
