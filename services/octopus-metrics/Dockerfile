FROM debian:trixie-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ cmake ninja-build pkg-config libpq-dev libcurl4-openssl-dev \
    libhiredis-dev libsimdjson-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source
COPY services/octopus-metrics services/octopus-metrics
COPY sql/postgres/octopus_core/manifest.yaml sql/postgres/octopus_core/manifest.yaml
RUN cmake -S services/octopus-metrics -B /build -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF && cmake --build /build --parallel 2
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 libcurl4t64 libhiredis1.1.0 libsimdjson25 libstdc++6 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/octopus-metrics /usr/local/bin/octopus-metrics
USER 65532:65532
EXPOSE 9092
ENTRYPOINT ["/usr/local/bin/octopus-metrics"]
