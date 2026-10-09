GO ?= go

.PHONY: test vet fmt-check build tidy

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	test -z "$$unformatted" || { printf '%s\n' "$$unformatted"; echo 'Run gofmt on the listed Go source files'; exit 1; }

build:
	$(GO) build -o /tmp/stats-reader ./cmd/stats-reader

tidy:
	$(GO) mod tidy
