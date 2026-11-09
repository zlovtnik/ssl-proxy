FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*

COPY docker/local/init-material.sh /usr/local/bin/init-local-material
RUN chmod 0555 /usr/local/bin/init-local-material

# Initialization owns the named volumes and PostgreSQL's UID 999 TLS key.
USER root
ENTRYPOINT ["/usr/local/bin/init-local-material"]
