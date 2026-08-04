# Schema Archive

This directory contains historical schema fragments retained for provenance.
They are not active migrations and must not be executed for a new environment.

The only canonical runtime manifests are:

- [`octopus_core`](../../sql/tidb/octopus_core/)
- [`atheros_search`](../../sql/tidb/atheros_search/)
- [`integration_console`](../../sql/tidb/integration_console/)
- [`schema_migrator`](../../sql/tidb/schema_migrator/)
- shared [`contracts`](../../sql/tidb/contracts/)

The provisioning schema executor applies those ordered, checksummed manifests.
PostgreSQL fixtures are valid only for Schema Migrator external-target tests;
Oracle material is deprecated or historical. See
[TiDB Runtime and Cutover](../tidb-runtime-cutover.md).
