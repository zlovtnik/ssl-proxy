FROM postgres:16-bookworm

RUN apt-get update -qq \
  && apt-get install -y --no-install-recommends \
    postgresql-16-cron \
    postgresql-16-pgvector \
  && rm -rf /var/lib/apt/lists/*

COPY docker/postgres/postgresql.conf /etc/postgresql/postgresql.conf
RUN chown postgres:postgres /etc/postgresql/postgresql.conf \
  && chmod 644 /etc/postgresql/postgresql.conf
