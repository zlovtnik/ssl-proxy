FROM coredns/coredns:1.12.3 AS coredns

FROM rust:1.86-slim AS builder
WORKDIR /app

# Install build dependencies required for openssl-sys
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    libclang-dev \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY src ./src
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release

FROM rust:1.86-slim AS boringtun-builder
RUN cargo install --locked boringtun-cli --version 0.5.2 --root /opt/boringtun

FROM debian:bookworm-slim
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.created=$BUILD_DATE
RUN apt-get update && apt-get install -y \
        bash \
        ca-certificates \
        curl \
        iproute2 \
        iptables \
        openssl \
        procps \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=coredns /coredns /usr/local/bin/coredns
COPY --from=builder /app/target/release/ssl-proxy .
COPY --from=boringtun-builder /opt/boringtun/bin/boringtun-cli /usr/local/bin/boringtun-cli
COPY --from=builder /app/target/release/wg-obfs-shim /usr/local/bin/wg-obfs-shim
COPY static ./static
COPY config/client ./client-config
COPY config/peer1/peer1-obfuscated.conf.example ./client-config/peer1-obfuscated.conf.example
COPY docker/entrypoint.sh /usr/local/bin/start-proxy-wg
RUN ldconfig && chmod +x /usr/local/bin/start-proxy-wg /usr/local/bin/wg-obfs-shim /usr/local/bin/boringtun-cli \
 && groupadd -r proxyuser && useradd -r -g proxyuser proxyuser \
 && chown -R proxyuser:proxyuser /app /usr/local/bin/start-proxy-wg /usr/local/bin/wg-obfs-shim /usr/local/bin/boringtun-cli \
 && setcap cap_net_admin+eip /usr/local/bin/coredns \
 && setcap cap_net_admin+eip /app/ssl-proxy \
 && setcap cap_net_admin+eip /usr/local/bin/boringtun-cli
ENV IMAGE_VCS_REF=$VCS_REF \
    IMAGE_BUILD_DATE=$BUILD_DATE \
    WG_CONFIG_PATH=/run/wireguard/wg0.conf \
    WG_TEMPLATE_PATH=/config/templates/server.conf \
    WG_UAPI_SOCKET_DIR=/var/run/wireguard \
    WG_SUDO=1 \
    COREDNS_CONFIG=/config/coredns/Corefile
EXPOSE 3000/tcp 3001/tcp 3002/tcp 443/udp
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3002/health || exit 1
# Running as root temporarily until entrypoint can drop privileges after network setup
# USER proxyuser
ENTRYPOINT ["/usr/local/bin/start-proxy-wg"]
