FROM ruby:3.4.4-slim

ENV BUNDLE_PATH=/bundle \
    BUN_INSTALL=/usr/local/bun \
    PATH=/usr/local/bun/bin:$PATH \
    RAILS_ENV=production \
    RAILS_LOG_TO_STDOUT=1 \
    RAILS_SERVE_STATIC_FILES=1 \
    TZ=America/New_York

WORKDIR /app

RUN apt-get update -qq \
  && apt-get install -y --no-install-recommends build-essential libpq-dev libyaml-dev pkg-config curl unzip tzdata \
  && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://bun.sh/install | bash \
  && ln -sf /usr/local/bun/bin/bun /usr/local/bin/bun \
  && bun --version

COPY apps/integration-console/Gemfile apps/integration-console/Gemfile.lock ./
RUN bundle install
COPY apps/integration-console/package.json apps/integration-console/bun.lock ./
RUN bun install --frozen-lockfile

COPY apps/integration-console ./
RUN bun run build

EXPOSE 3000

CMD ["bin/rails", "server", "-b", "0.0.0.0"]
