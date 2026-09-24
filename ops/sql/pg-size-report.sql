-- Read-only storage report for the sync database. Every statement is a
-- SELECT: running this file never changes database state. The query text is
-- consumed by ops/disk/audit.sh and ops/sql/pg-size-report.sh.

SELECT now() AS observed_at, current_database() AS database;

SELECT datname,
       pg_size_pretty(pg_database_size(datname)) AS total,
       pg_database_size(datname) AS bytes
FROM pg_database
WHERE datistemplate = false
ORDER BY pg_database_size(datname) DESC;

SELECT n.nspname AS schema,
       c.relname AS relation,
       case c.relkind when 'p' then 'partitioned' when 'm' then 'materialized' else 'table' end AS kind,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS total,
       pg_size_pretty(pg_table_size(c.oid)) AS heap,
       pg_size_pretty(pg_indexes_size(c.oid)) AS indexes,
       pg_size_pretty(greatest(pg_total_relation_size(c.oid) - pg_table_size(c.oid) - pg_indexes_size(c.oid), 0)) AS toast,
       coalesce(s.n_live_tup, 0) AS live_tuples,
       coalesce(s.n_dead_tup, 0) AS dead_tuples,
       s.last_autovacuum,
       s.last_vacuum
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
WHERE n.nspname IN ('octopus_core', 'atheros_search', 'schema_migrator', 'keycloak', 'public')
  AND c.relkind IN ('r', 'p', 'm')
ORDER BY pg_total_relation_size(c.oid) DESC
LIMIT 25;

SELECT n.nspname AS schema,
       c.relname AS relation,
       coalesce(s.n_live_tup, 0) AS live_tuples,
       coalesce(s.n_dead_tup, 0) AS dead_tuples,
       s.last_autovacuum,
       s.last_vacuum
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
WHERE n.nspname IN ('octopus_core', 'atheros_search', 'schema_migrator', 'keycloak', 'public')
  AND c.relkind = 'r'
ORDER BY coalesce(s.n_dead_tup, 0) DESC
LIMIT 20;

SELECT name, setting, unit
FROM pg_settings
WHERE name IN ('max_wal_size', 'min_wal_size', 'checkpoint_timeout', 'shared_buffers',
               'autovacuum_vacuum_scale_factor', 'autovacuum_naptime')
ORDER BY name;

SELECT slot_name,
       slot_type,
       active,
       pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS retained_wal
FROM pg_replication_slots
ORDER BY retained_wal DESC NULLS LAST;

SELECT n.nspname AS schema,
       c.relname AS relation,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS total,
       pg_total_relation_size(c.oid) AS bytes
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE (n.nspname, c.relname) IN (
        ('octopus_core', 'sync_batches'),
        ('octopus_core', 'sync_events'),
        ('octopus_core', 'ingestion_evidence'),
        ('atheros_search', 'embeddings'),
        ('atheros_search', 'search_vectors_event')
      )
ORDER BY pg_total_relation_size(c.oid) DESC;
