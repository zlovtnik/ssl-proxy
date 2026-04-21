FROM rust:1.86-slim AS builder
WORKDIR /app/services/oracle-worker
COPY services/oracle-worker/Cargo.toml services/oracle-worker/Cargo.lock ./
COPY services/oracle-worker/src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libaio1 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/services/oracle-worker/target/release/oracle-worker /usr/local/bin/oracle-worker
CMD ["/usr/local/bin/oracle-worker", "run"]
