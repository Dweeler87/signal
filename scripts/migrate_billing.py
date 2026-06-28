"""
Migration: add Stripe billing columns to signal.api_keys.

Run once before deploying billing endpoints:
    python scripts/migrate_billing.py

ClickHouse ADD COLUMN is non-blocking and safe on live tables.
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
    "ALTER TABLE signal.api_keys ADD COLUMN IF NOT EXISTS stripe_customer_id Nullable(String)",
    "ALTER TABLE signal.api_keys ADD COLUMN IF NOT EXISTS stripe_subscription_id Nullable(String)",
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
