FROM coredns/coredns:1.12.3 AS coredns

FROM rust:1.95.0-slim-bookworm AS builder
WORKDIR /app

# Install build dependencies required for openssl-sys
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    cmake \
    build-essential \
    libclang-dev \
    pkg-config \
    libssl-dev \
    libpcap-dev \
    libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY src ./src
COPY benches ./benches
COPY crates ./crates
COPY services/atheros-sensor ./services/atheros-sensor
COPY services/db-migrator ./services/db-migrator
COPY Cargo.toml Cargo.lock ./
RUN cargo build --release --workspace && cargo build --release --manifest-path services/atheros-sensor/Cargo.toml

FROM rust:1.95.0-slim-bookworm AS boringtun-builder
RUN cargo install --locked boringtun-cli --version 0.5.2 --root /opt/boringtun

FROM debian:bookworm-slim AS atheros-sensor
ENV TZ=America/New_York
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.created=$BUILD_DATE
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        iproute2 \
        iptables \
        iw \
        libcap2-bin \
        libpcap0.8 \
        openssl \
        procps \
        tzdata \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/atheros-sensor /usr/local/bin/atheros-sensor
RUN ldconfig && chmod +x /usr/local/bin/atheros-sensor \
  && groupadd -r proxyuser && useradd -r -g proxyuser proxyuser \
  && chown -R proxyuser:proxyuser /app /usr/local/bin/atheros-sensor \
  && setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/atheros-sensor \
  && setcap cap_net_admin+eip /usr/sbin/iw
USER proxyuser
CMD ["/usr/local/bin/atheros-sensor"]

FROM debian:bookworm-slim AS ssl-proxy
ENV TZ=America/New_York
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.created=$BUILD_DATE
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        iproute2 \
        iptables \
        iw \
        libcap2-bin \
        libpcap0.8 \
        openssl \
        procps \
        tzdata \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=coredns /coredns /usr/local/bin/coredns
COPY --from=builder /app/target/release/ssl-proxy .
COPY --from=builder /app/target/release/wg-udp-frontdoor /usr/local/bin/wg-udp-frontdoor
COPY --from=boringtun-builder /opt/boringtun/bin/boringtun-cli /usr/local/bin/boringtun-cli
COPY --from=builder /app/target/release/wg-obfs-shim /usr/local/bin/wg-obfs-shim
COPY static ./static
COPY config/client ./client-config
COPY config/peer1/peer1-obfuscated.conf.example ./client-config/peer1-obfuscated.conf.example
COPY docker/entrypoint.sh /usr/local/bin/start-proxy-wg
RUN ldconfig && chmod +x /usr/local/bin/start-proxy-wg /usr/local/bin/wg-obfs-shim /usr/local/bin/wg-udp-frontdoor /usr/local/bin/boringtun-cli \
  && groupadd -r proxyuser && useradd -r -g proxyuser proxyuser \
  && chown -R proxyuser:proxyuser /app /usr/local/bin/start-proxy-wg /usr/local/bin/wg-obfs-shim /usr/local/bin/wg-udp-frontdoor /usr/local/bin/boringtun-cli \
  && setcap cap_net_admin+eip /usr/local/bin/coredns \
  && setcap cap_net_admin+eip /app/ssl-proxy \
  && setcap cap_net_bind_service+eip /usr/local/bin/wg-udp-frontdoor \
  && setcap cap_net_admin+eip /usr/local/bin/boringtun-cli \
  && setcap cap_net_admin+eip /usr/sbin/iw
USER proxyuser
CMD ["/usr/local/bin/start-proxy-wg"]
