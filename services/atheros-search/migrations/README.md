The canonical Atheros Search runtime schema is managed in the repository-level
TiDB domain under `sql/tidb/atheros_search/`.

Keep service-local migrations here only if this module gains schema objects that
are not part of the shared runtime database. The service verifies the canonical
manifest checksum at startup and never applies DDL itself.
