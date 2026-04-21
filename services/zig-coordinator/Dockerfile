FROM alpine:3.20 AS builder
ARG ZIG_VERSION=0.16.0
ARG TARGETARCH
WORKDIR /app/services/zig-coordinator
RUN apk add --no-cache ca-certificates curl xz \
 && docker_arch="${TARGETARCH}" \
 && if [ -z "${docker_arch}" ]; then docker_arch="$(apk --print-arch)"; fi \
 && case "${docker_arch}" in \
        amd64) zig_arch="x86_64" ;; \
        arm64) zig_arch="aarch64" ;; \
        arm) zig_arch="arm" ;; \
        x86_64|aarch64|x86) zig_arch="${docker_arch}" ;; \
        386) zig_arch="x86" ;; \
        ppc64le|riscv64|s390x) zig_arch="${docker_arch}" ;; \
        *) echo "unsupported TARGETARCH: ${docker_arch}" >&2; exit 1 ;; \
    esac \
 && curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${zig_arch}-linux-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz \
 && tar -xJf /tmp/zig.tar.xz -C /opt \
 && ln -s "/opt/zig-${zig_arch}-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig \
 && rm -f /tmp/zig.tar.xz

COPY . .
RUN zig build -Doptimize=ReleaseSafe

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        netcat-openbsd \
        postgresql-client \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/services/zig-coordinator/zig-out/bin/zig-coordinator /usr/local/bin/zig-coordinator
COPY services/zig-coordinator/schema ./schema
ENV SYNC_SCHEMA_FILE=/app/schema/postgres.sql
CMD ["/usr/local/bin/zig-coordinator", "run"]
