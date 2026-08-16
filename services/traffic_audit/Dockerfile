FROM --platform=$BUILDPLATFORM elixir:1.17-slim AS builder

WORKDIR /app
ENV MIX_ENV=prod \
    ELIXIR_ERL_OPTS="+sbwt none +sbwtdcpu none +sbwtdcs none"

# CA certs are required for `mix deps.get` over HTTPS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY mix.exs mix.lock ./
COPY config config
COPY lib lib
COPY priv priv

RUN mix local.hex --force && mix local.rebar --force \
    && mix deps.get --only prod \
    && mix deps.compile \
    && mix escript.build

# Runtime image — only the built escript + capture/classification tooling.
# tshark is intentionally omitted: Debian bookworm's Wireshark 4.x removed
# `ja3,tree`, so `Io.Ja3` degrades to no fingerprints (L4 weight is 0.0).
# Privileged (NET_RAW/NET_ADMIN) is granted by the CI runner at the container
# cap level, never baked into the image.
FROM elixir:1.17-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        tcpdump \
        libndpi-bin \
    && rm -rf /var/lib/apt/lists/*

ARG USER=traffic-audit
RUN useradd --create-home --home-dir /home/$USER --shell /bin/sh $USER

WORKDIR /app
COPY --from=builder /app/traffic-audit /usr/local/bin/traffic-audit
# Fixture pcaps are needed by unprivileged fixture-mode runs (PR CI).
COPY --from=builder /app/priv/fixtures /app/priv/fixtures

USER $USER

ENTRYPOINT ["traffic-audit"]
CMD ["help"]