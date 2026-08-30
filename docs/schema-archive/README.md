> **Status: Historical / superseded.**

# Schema Archive

This document contains historical schema material and references that must not be used as current runtime definitions.

This directory contains historical schema fragments retained for provenance.
They are not active migrations and must not be executed for a new environment.

The only canonical runtime manifests are:

- [`octopus_core`](../../sql/postgres/octopus_core/)
- [`atheros_search`](../../sql/postgres/atheros_search/)
- [`schema_migrator`](../../sql/postgres/schema_migrator/)
- [`keycloak`](../../sql/postgres/keycloak/)
- shared [`contracts`](../../sql/postgres/contracts/)

The provisioning schema executor applies those ordered, checksummed manifests.
PostgreSQL fixtures are valid only for Schema Migrator external-target tests;
Oracle material is deprecated or historical. See
[PostgreSQL runtime manifests](../../sql/postgres/).
