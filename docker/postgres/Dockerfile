FROM postgres:16-bookworm

RUN apt-get update -qq \
  && apt-get install -y --no-install-recommends \
    postgresql-16-cron \
    postgresql-16-pgvector \
  && rm -rf /var/lib/apt/lists/*
