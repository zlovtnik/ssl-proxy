FROM postgres:16-bookworm

RUN apt-get update -qq \
  && apt-get install -y --no-install-recommends \
    postgresql-16-cron \
    postgresql-16-pgvector \
  && rm -rf /var/lib/apt/lists/*

COPY docker/postgres/postgresql.conf /etc/postgresql/postgresql.conf
COPY docker/postgres/010-schema.sql /docker-entrypoint-initdb.d/010-schema.sql
COPY sql /docker-entrypoint-initdb.d/schema

RUN chown postgres:postgres \
    /etc/postgresql/postgresql.conf \
    /docker-entrypoint-initdb.d/010-schema.sql \
  && chown -R postgres:postgres /docker-entrypoint-initdb.d/schema \
  && chmod 644 /etc/postgresql/postgresql.conf
