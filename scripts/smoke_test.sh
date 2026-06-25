#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${DATABASE_URL:?DATABASE_URL is required}"
export DATABASE_URL

cd "${repo_root}/services/schema-migrator"
sbt "run --sql-dir ../../sql list"
sbt "run --sql-dir ../../sql validate"
sbt "run --sql-dir ../../sql apply"
