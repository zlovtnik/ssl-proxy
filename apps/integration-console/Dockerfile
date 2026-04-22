FROM ruby:3.4.4-slim

ENV BUNDLE_PATH=/bundle \
    RAILS_ENV=production \
    RAILS_LOG_TO_STDOUT=1 \
    RAILS_SERVE_STATIC_FILES=1

WORKDIR /app

RUN apt-get update -qq \
  && apt-get install -y --no-install-recommends build-essential libpq-dev libyaml-dev pkg-config curl \
  && rm -rf /var/lib/apt/lists/*

COPY apps/integration-console/Gemfile apps/integration-console/Gemfile.lock ./
RUN bundle install

COPY apps/integration-console ./

EXPOSE 3000

CMD ["bin/rails", "server", "-b", "0.0.0.0"]
