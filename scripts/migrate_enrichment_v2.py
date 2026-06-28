"""
Migration: add extended enrichment columns to signal.domains table.

Run once on the production ClickHouse instance before deploying the updated worker:
    python scripts/migrate_enrichment_v2.py

ClickHouse ADD COLUMN is non-blocking and safe to run on live tables.
Existing rows will read NULL for the new columns until re-enriched.
"""

import sys

import clickhouse_connect
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    clickhouse_host: str
    clickhouse_port: int = 8443
    clickhouse_user: str = "default"
    clickhouse_password: str
    clickhouse_database: str = "signal"

    class Config:
        env_file = ".env"
        extra = "ignore"


MIGRATIONS = [
    "ALTER TABLE signal.domains ADD COLUMN IF NOT EXISTS txt_vendor Nullable(String)",
    "ALTER TABLE signal.domains ADD COLUMN IF NOT EXISTS http_tech Nullable(String)",
    "ALTER TABLE signal.domains ADD COLUMN IF NOT EXISTS is_live Nullable(Bool)",
    "ALTER TABLE signal.domains ADD COLUMN IF NOT EXISTS domain_registered_at Nullable(DateTime)",
]


def main() -> None:
    settings = Settings()
    client = clickhouse_connect.get_client(
        host=settings.clickhouse_host,
        port=settings.clickhouse_port,
        username=settings.clickhouse_user,
        password=settings.clickhouse_password,
        secure=True,
    )

    for stmt in MIGRATIONS:
        try:
            client.command(stmt)
            print(f"  OK  {stmt}")
        except Exception as exc:
            print(f"  ERR {stmt}\n      {exc}", file=sys.stderr)
            sys.exit(1)

    print("\nMigration complete.")


if __name__ == "__main__":
    main()
