# Atheros Search service-local migrations

This directory does not own the shared runtime schema. Canonical Atheros Search
DDL and its checksummed apply order live in
[`sql/postgres/atheros_search`](../../../sql/postgres/atheros_search/).

Add a migration here only for a future object that is truly private to this Go
module and independent of the repository runtime contract. Atheros Search
verifies the canonical manifest at startup and never applies DDL.

See [canonical PostgreSQL manifests](../../../sql/postgres/atheros_search/).
