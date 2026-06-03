Database migrations for atheros-search are currently managed in the repository-level
Postgres schema under `sql/`.

Keep service-local migrations here only if this module gains schema objects that
are not part of the shared sync/vector database.
