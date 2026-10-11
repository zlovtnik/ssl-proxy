"""Run the Go privilege regressions against ephemeral PostgreSQL Testcontainers."""
import os
from pathlib import Path
import subprocess

from testcontainers.community.postgres import PostgresContainer


SERVICE = Path(__file__).resolve().parents[1]
IMAGE = "postgres:16.15-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685"


def main():
    with PostgresContainer(IMAGE, username="fixture", password="fixture-only",
                           dbname="metrics_grants") as postgres:
        env = dict(os.environ, PLATFORM_SYNC_TEST_POSTGRES_DSN=
                   postgres.get_connection_url().replace("postgresql+psycopg2://", "postgresql://"))
        return subprocess.run(["go", "test", "-race", "-tags=integration", "./..."],
                              cwd=SERVICE, env=env, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
