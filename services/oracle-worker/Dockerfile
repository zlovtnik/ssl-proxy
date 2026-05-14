FROM rust:1.88-slim AS builder
WORKDIR /app/services/oracle-worker
COPY services/oracle-worker/Cargo.toml services/oracle-worker/Cargo.lock ./
COPY services/oracle-worker/src ./src
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        cmake \
        libaio-dev \
        libclang-dev \
        libssl-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN cargo build --release

FROM debian:bookworm-slim
ENV TZ=America/New_York
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        cmake \
        make \
        tzdata \
        libaio1 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/services/oracle-worker/target/release/oracle-worker /usr/local/bin/oracle-worker
CMD ["/usr/local/bin/oracle-worker", "run"]
