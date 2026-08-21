FROM mysql:8.0

WORKDIR /workspace
COPY sql/tidb /workspace/sql/tidb
COPY k8s/tidb-schema-executor/entrypoint.sh /usr/local/bin/tidb-runtime-schema
COPY k8s/tidb-schema-executor/bootstrap.sh /usr/local/bin/tidb-bootstrap

RUN chmod 0555 /usr/local/bin/tidb-runtime-schema /usr/local/bin/tidb-bootstrap

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/tidb-runtime-schema"]
