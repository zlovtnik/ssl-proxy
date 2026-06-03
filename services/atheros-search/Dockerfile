FROM golang:1.26-bookworm AS builder
WORKDIR /src/services/atheros-search

COPY services/atheros-search/go.mod services/atheros-search/go.sum* ./
RUN go mod download

COPY services/atheros-search ./
RUN CGO_ENABLED=1 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/atheros-search ./cmd/server

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /out/atheros-search /usr/local/bin/atheros-search
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/atheros-search"]
