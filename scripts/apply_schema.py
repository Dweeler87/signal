"""Apply db/schema.sql to the configured ClickHouse instance.

Run once after provisioning ClickHouse Cloud:
    python scripts/apply_schema.py
"""

import pathlib
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


def main() -> None:
    settings = Settings()
    schema_path = pathlib.Path(__file__).parent.parent / "db" / "schema.sql"
    sql = schema_path.read_text()

    client = clickhouse_connect.get_client(
        host=settings.clickhouse_host,
        port=settings.clickhouse_port,
        username=settings.clickhouse_user,
        password=settings.clickhouse_password,
        secure=True,
    )

    # Split on semicolons, skip empty statements
    statements = [s.strip() for s in sql.split(";") if s.strip()]
    for stmt in statements:
        try:
            client.command(stmt)
            # Print just the first line of each statement for readability
            print(f"  OK  {stmt.splitlines()[0][:80]}")
        except Exception as exc:
            print(f"  ERR {stmt.splitlines()[0][:80]}\n      {exc}", file=sys.stderr)
            sys.exit(1)

    print("\nSchema applied successfully.")


if __name__ == "__main__":
    main()
