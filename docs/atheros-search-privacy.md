# Atheros Search Privacy

Search analytics rows in `search_queries` are retained for 30 days by default
through `expires_at` and the `search_purge_expired_queries()` cron job.

Application write paths must not store raw `query_text`, `session_id`, or
`result_keys` for analytics. Store `hashed_query_text`, `session_hash`, and
`result_key_hashes` instead. The raw `query_text` and `result_keys` columns are
nullable and reserved for explicit diagnostic opt-in flows that document consent
and retention expectations.
