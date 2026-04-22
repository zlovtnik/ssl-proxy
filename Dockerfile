FROM coredns/coredns:1.12.3 AS coredns

FROM rust:1.86-slim AS builder
WORKDIR /app

# Install build dependencies required for openssl-sys
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    libclang-dev \
    pkg-config \
    libssl-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY src ./src
COPY services/atheros-sensor ./services/atheros-sensor
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release --workspace && cargo build --release --manifest-path services/atheros-sensor/Cargo.toml

FROM rust:1.86-slim AS boringtun-builder
RUN cargo install --locked boringtun-cli --version 0.5.2 --root /opt/boringtun

FROM debian:bookworm-slim AS atheros-sensor
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
        libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=coredns /coredns /usr/local/bin/coredns
COPY --from=builder /app/target/release/ssl-proxy .
COPY --from=boringtun-builder /opt/boringtun/bin/boringtun-cli /usr/local/bin/boringtun-cli
COPY --from=builder /app/target/release/wg-obfs-shim /usr/local/bin/wg-obfs-shim
COPY --from=builder /app/target/release/atheros-sensor /usr/local/bin/atheros-sensor
COPY static ./static
COPY config/client ./client-config
COPY config/peer1/peer1-obfuscated.conf.example ./client-config/peer1-obfuscated.conf.example
COPY docker/entrypoint.sh /usr/local/bin/start-proxy-wg
RUN ldconfig && chmod +x /usr/local/bin/start-proxy-wg /usr/local/bin/wg-obfs-shim /usr/local/bin/boringtun-cli /usr/local/bin/atheros-sensor \
  && groupadd -r proxyuser && useradd -r -g proxyuser proxyuser \
  && chown -R proxyuser:proxyuser /app /usr/local/bin/start-proxy-wg /usr/local/bin/wg-obfs-shim /usr/local/bin/boringtun-cli /usr/local/bin/atheros-sensor \
  && setcap cap_net_admin+eip /usr/local/bin/coredns \
  && setcap cap_net_admin+eip /app/ssl-proxy \
  && setcap cap_net_admin+eip /usr/local/bin/boringtun-cli \
  && setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/atheros-sensor
USER proxyuser
CMD ["/usr/local/bin/atheros-sensor"]
