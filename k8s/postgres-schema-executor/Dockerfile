FROM postgres:16.15-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685

WORKDIR /workspace
COPY sql/postgres /workspace/sql/postgres
COPY k8s/postgres-schema-executor/entrypoint.sh /usr/local/bin/postgres-runtime-schema
RUN chmod 0555 /usr/local/bin/postgres-runtime-schema

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/postgres-runtime-schema"]
