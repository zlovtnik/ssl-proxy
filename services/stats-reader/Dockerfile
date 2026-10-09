# Base images use version tags, matching apps/integration-console/atheros-search.
# Production workload images are pinned by digest at the Kubernetes layer.
FROM golang:1.26-bookworm AS builder
WORKDIR /src/services/stats-reader

COPY services/stats-reader/go.mod services/stats-reader/go.sum ./
RUN go mod download

COPY services/stats-reader ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/stats-reader ./cmd/stats-reader

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/stats-reader /usr/local/bin/stats-reader
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/stats-reader"]
