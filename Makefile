# Root task runner. Application tasks live in siemagent/Makefile; this file
# delegates to it and adds the cross-stack quality gate that CI runs.

APP := siemagent
WEB := $(APP)/web

.PHONY: help hooks quality-gate quality-go quality-web test test-integration lint \
        build dev serve docker-up docker-down pull-models seed setup

help:
	@echo "make hooks             Install git hooks (.githooks/)"
	@echo "make quality-gate      Everything CI checks (Go + web)"
	@echo "make test              Go unit tests (race detector)"
	@echo "make test-integration  Go integration tests (needs make docker-up)"
	@echo "make lint              go vet + golangci-lint + oxlint"
	@echo "make dev               Backend :8080 + dashboard :5173"
	@echo "make docker-up         Start Qdrant, Ollama and Postgres"
	@echo "Other targets: build serve docker-down pull-models seed setup"

hooks:
	git config core.hooksPath .githooks
	@echo "Git hooks installed from .githooks/"

quality-gate: quality-go quality-web

quality-go:
	cd $(APP) && test -z "$$(gofmt -l cmd internal pkg)" || { gofmt -l cmd internal pkg; exit 1; }
	cd $(APP) && go vet ./... && go vet -tags integration ./...
	cd $(APP) && golangci-lint run --build-tags integration ./...
	cd $(APP) && go test -race -timeout 120s ./...
	cd $(APP) && go build ./cmd/siemagent

quality-web:
	cd $(WEB) && npm run lint && npx tsc -b && npm test && npx vite build

test:
	cd $(APP) && go test -race -timeout 120s ./...

test-integration:
	cd $(APP) && \
	  POSTGRES_TEST_DSN=$${POSTGRES_TEST_DSN:-postgres://siemagent:siemagent@localhost:5433/siemagent?sslmode=disable} \
	  go test -race -tags integration -timeout 180s ./internal/store/... ./internal/incident/... ./pkg/qdrant/...

lint:
	cd $(APP) && go vet ./... && golangci-lint run --build-tags integration ./...
	cd $(WEB) && npm run lint

build dev serve docker-up docker-down pull-models seed setup:
	$(MAKE) -C $(APP) $@
