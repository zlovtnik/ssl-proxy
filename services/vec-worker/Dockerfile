FROM rust:1.86-slim AS builder
WORKDIR /app/services/vec-worker

# Install build dependencies for sqlx and reqwest
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    cmake \
    libclang-dev \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY services/vec-worker/Cargo.toml services/vec-worker/Cargo.lock ./
COPY services/vec-worker/src ./src
RUN cargo build --release

FROM debian:bookworm-slim
ENV TZ=America/New_York
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/services/vec-worker/target/release/vec-worker /usr/local/bin/vec-worker

CMD ["/usr/local/bin/vec-worker"]