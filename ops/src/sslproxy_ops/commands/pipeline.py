from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Annotated

import typer

from sslproxy_ops import shell
from sslproxy_ops.config import Settings
from sslproxy_ops.util.ini import uri_encode

app = typer.Typer(help="Sync pipeline operations.")


@dataclass(frozen=True, slots=True)
class SqlSection:
    title: str
    sql: str


SQL_SECTIONS = [
    SqlSection(
        "postgres sync counts",
        """
select 'sync_events' table_name, count(*) from sync_events
union all select 'sync_cursors', count(*) from sync_cursors
union all select 'sync_jobs', count(*) from sync_jobs
union all select 'sync_batches', count(*) from sync_batches
union all select 'sync_errors', count(*) from sync_errors
union all select 'sync_backlog', count(*) from sync_backlog
order by table_name;
""",
    ),
    SqlSection(
        "recent ingest",
        """
select observed_at, stream_name, status, producer, event_kind, left(dedupe_key, 16) as dedupe
from sync_events
order by updated_at desc
limit 10;
""",
    ),
    SqlSection(
        "wireless audit counts (last 24h)",
        """
select
  status,
  stream_name,
  count(*),
  min(observed_at) as oldest,
  max(observed_at) as newest
from sync_events
where stream_name = 'wireless.audit'
  and observed_at >= now() - interval '24 hours'
group by status, stream_name
order by status;
""",
    ),
    SqlSection(
        "wireless audit threat detections",
        """
select
  coalesce(ssid, payload->>'ssid') as ssid,
  coalesce(source_mac, payload->>'source_mac') as source_mac,
  case
    when tags is not null and tags <> '[]'::jsonb then tags
    when jsonb_typeof(payload->'tags') = 'array' then payload->'tags'
    else '[]'::jsonb
  end as threat_tags,
  payload_archived,
  payload_archive_uri,
  observed_at
from sync_events_expanded
where stream_name = 'wireless.audit'
  and (
    coalesce(handshake_captured, false)
    or exists (
      select 1
      from jsonb_array_elements_text(
        case
          when tags is not null and tags <> '[]'::jsonb then tags
          when jsonb_typeof(payload->'tags') = 'array' then payload->'tags'
          else '[]'::jsonb
        end
      ) tag(value)
      where tag.value like 'threat:%'
    )
  )
order by observed_at desc
limit 20;
""",
    ),
    SqlSection(
        "postgres retention health",
        """
select
  hot_payload_count,
  pg_size_pretty(hot_payload_bytes) as hot_payload_size,
  unarchived_payload_count,
  oldest_unarchived_payload_at,
  archive_lag_seconds,
  archived_payload_count,
  pg_size_pretty(archived_payload_bytes) as archived_payload_size,
  tombstone_count,
  expired_tombstone_count,
  vector_rows_by_kind
from v_postgres_storage_health;
""",
    ),
    SqlSection(
        "postgres relation storage",
        """
select
  relname as relation,
  pg_size_pretty(pg_total_relation_size(relid)) as total_size,
  pg_size_pretty(pg_relation_size(relid)) as table_size,
  pg_size_pretty(pg_total_relation_size(relid) - pg_relation_size(relid)) as index_size,
  n_live_tup as live_tuples,
  n_dead_tup as dead_tuples,
  round(
    case when n_live_tup + n_dead_tup > 0
      then n_dead_tup::numeric / nullif(n_live_tup + n_dead_tup, 0)
      else 0::numeric
    end,
    4
  ) as dead_tuple_ratio,
  last_autovacuum
from pg_stat_user_tables
where relname in (
  'sync_events',
  'wireless_frames',
  'sync_event_payload_archives',
  'sync_event_tombstones',
  'vec_embeddings',
  'vec_embedding_jobs',
  'vec_similarity_pairs'
)
order by pg_total_relation_size(relid) desc;
""",
    ),
]


def database_url(settings: Settings) -> str:
    if settings.database_url:
        return settings.database_url
    if not settings.postgres_password:
        raise typer.BadParameter("POSTGRES_PASSWORD is required when DATABASE_URL is unset")
    return f"postgres://sync:{uri_encode(settings.postgres_password)}@postgres:5432/sync"


def section(title: str) -> None:
    typer.echo("")
    typer.echo(f"== {title} ==")


def run_allow_fail(cmd: list[str]) -> None:
    shell.run(cmd, check=False, capture=False)


@app.command("status")
def status(
    scan_topic: Annotated[
        str | None,
        typer.Option("--scan-topic", envvar="SYNC_SCAN_TOPIC"),
    ] = None,
    scan_consumer: Annotated[
        str | None,
        typer.Option("--scan-consumer", envvar="SYNC_SCAN_CONSUMER"),
    ] = None,
) -> None:
    settings = Settings()
    scan_topic = scan_topic or settings.sync_scan_topic
    scan_consumer = scan_consumer or settings.sync_scan_consumer
    db_url = database_url(settings)
    brokers = settings.sync_redpanda_bootstrap_servers
    compose_project = settings.compose_project_name
    redpanda_image = settings.redpanda_image

    typer.echo("== compose services ==")
    run_allow_fail(
        [
            "docker",
            "compose",
            "ps",
            "redpanda",
            "postgres",
            "redpanda-init",
            "java-coordinator",
            "java-coordinator-2",
            "java-coordinator-3",
            "atheros-sensor",
        ]
    )

    rpk_base = [
        "docker",
        "run",
        "--rm",
        "--network",
        f"{compose_project}_default",
        "--entrypoint",
        "rpk",
        redpanda_image,
    ]
    section("redpanda cluster")
    run_allow_fail([*rpk_base, "cluster", "info", "--brokers", brokers])
    section("redpanda topics")
    run_allow_fail([*rpk_base, "topic", "list", "--brokers", brokers])
    section("redpanda scan topic")
    run_allow_fail([*rpk_base, "topic", "describe", scan_topic, "--brokers", brokers])
    section("redpanda scan consumer group")
    run_allow_fail([*rpk_base, "group", "describe", scan_consumer, "--brokers", brokers])

    env = {**os.environ, "DATABASE_URL": db_url}
    for sql_section in SQL_SECTIONS:
        section(sql_section.title)
        shell.run(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "postgres",
                "psql",
                db_url,
                "-v",
                "ON_ERROR_STOP=1",
                "-c",
                sql_section.sql,
            ],
            check=False,
            env=env,
        )

