import clickhouse_connect
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    clickhouse_host: str
    clickhouse_port: int = 8443
    clickhouse_user: str = "default"
    clickhouse_password: str
    clickhouse_database: str = "signal"
    redis_url: str = "redis://localhost:6379"
    log_level: str = "info"
    # On first run, start this many entries before the log head (0 = replay all)
    initial_lookback: int = 2000
    # PDL Company API key (optional — enrichment skipped if not set)
    pdl_api_key: str = ""
    # Enrichment worker settings
    enrichment_batch_size: int = 100
    enrichment_poll_interval: int = 5  # seconds between polls

    class Config:
        env_file = ".env"


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def get_client() -> clickhouse_connect.driver.Client:
    s = get_settings()
    return clickhouse_connect.get_client(
        host=s.clickhouse_host,
        port=s.clickhouse_port,
        username=s.clickhouse_user,
        password=s.clickhouse_password,
        database=s.clickhouse_database,
        secure=True,
    )
