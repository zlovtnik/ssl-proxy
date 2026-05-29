#!/usr/bin/env bash
set -euo pipefail

cargo build --release -p db-migrator
./target/release/db-migrator list --sql-dir ./sql
./target/release/db-migrator validate --sql-dir ./sql
./target/release/db-migrator apply --sql-dir ./sql --database-url "$DATABASE_URL"
