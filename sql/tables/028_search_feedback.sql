-- object: search query log and feedback
-- folder: tables
-- depends_on: pgvector extension
create table if not exists search_queries (
  query_id    bigserial primary key,
  query_text  text not null,
  query_kind  text not null,
  query_vec   vector,
  top_k       integer not null default 10,
  result_keys text[] not null default '{}',
  session_id  text,
  latency_ms  integer,
  created_at  timestamptz not null default now()
);

create index if not exists search_queries_created_idx
  on search_queries (created_at desc);

create table if not exists search_feedback (
  feedback_id bigserial primary key,
  query_id    bigint not null references search_queries(query_id) on delete cascade,
  source_key  text not null,
  relevant    boolean not null,
  created_at  timestamptz not null default now()
);

create index if not exists search_feedback_query_idx
  on search_feedback (query_id, source_key);

