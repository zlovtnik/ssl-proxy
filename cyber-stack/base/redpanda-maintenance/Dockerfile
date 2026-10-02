FROM redpandadata/redpanda:v24.2.7@sha256:82a69763bef8d8b55ea5a520fa1b38f993908ef68946819ca1aed43541824c48 AS redpanda

FROM alpine:3.21

RUN apk add --no-cache bash coreutils curl jq postgresql16-client
# /usr/bin/rpk is a wrapper that requires Redpanda's installation tree.
COPY --from=redpanda /opt/redpanda/libexec/rpk /usr/local/bin/rpk
RUN rpk version

USER 65532:65532
ENTRYPOINT ["/bin/bash"]
