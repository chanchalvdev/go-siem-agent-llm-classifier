BIN     := siemagent
BINARY  := ./bin/$(BIN)
WEB_DIR := web
PORT   ?= $${CONDUCTOR_PORT:-8080}
# Load .env into the environment of run/serve/dev (the Go binary reads os env only).
LOAD_ENV := set -a; [ -f .env ] && . ./.env; set +a;

.PHONY: help build build-all build-frontend embed-binary \
        run serve dev \
        test test-integration vet lint \
        setup docker-up docker-down pull-models \
        seed clean check-env

# ── Default ────────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "  Go SIEM Agent — LLM Classifier"
	@echo ""
	@echo "  Setup"
	@echo "    make setup          Create .env, download Go deps, install npm deps"
	@echo "    make docker-up      Start Qdrant, Postgres, Ollama via Docker"
	@echo "    make docker-down    Stop Docker services"
	@echo "    make pull-models    Pull required Ollama embedding models"
	@echo ""
	@echo "  Development"
	@echo "    make dev            Run Go backend + Vite frontend in parallel"
	@echo "    make serve          Build and run HTTP server only (port 8080)"
	@echo "    make run            Build and run CLI mode against sample.log"
	@echo ""
	@echo "  Build"
	@echo "    make build          Build Go binary"
	@echo "    make build-all      Build frontend + embed into Go binary"
	@echo ""
	@echo "  Quality"
	@echo "    make test           Run all unit tests with race detector"
	@echo "    make test-integration  Run integration tests (needs Qdrant)"
	@echo "    make vet            Run go vet"
	@echo "    make lint           Run golangci-lint (install if missing)"
	@echo ""
	@echo "  Utilities"
	@echo "    make seed           Send 10 sample syslog events to /classify"
	@echo "    make clean          Remove build artifacts"
	@echo ""

# ── Build ──────────────────────────────────────────────────────────────────────

build:
	@mkdir -p bin
	go build -o $(BINARY) ./cmd/siemagent
	@echo "Built: $(BINARY)"

build-frontend:
	cd $(WEB_DIR) && npm run build

embed-binary: build-frontend
	@mkdir -p bin
	go build -ldflags="-s -w" -o $(BINARY) ./cmd/siemagent
	@echo "Binary built with embedded frontend: $(BINARY)"

build-all: embed-binary

# ── Run ───────────────────────────────────────────────────────────────────────

run: check-env build
	@$(LOAD_ENV) $(BINARY) sample.log

serve: check-env build
	@$(LOAD_ENV) $(BINARY) --serve --port $(PORT)

# ── Dev (live reload) ─────────────────────────────────────────────────────────

dev: check-env
	@echo "Starting Go backend + Vite frontend..."
	@$(LOAD_ENV) trap 'kill 0' SIGINT SIGTERM; \
	  (cd $(WEB_DIR) && npm run dev) & \
	  (air -c .air.toml 2>/dev/null || go run ./cmd/siemagent --serve --port $(PORT)) & \
	  wait

# ── Test ──────────────────────────────────────────────────────────────────────

test:
	go test ./... -v -race -timeout 60s

test-integration:
	go test -tags integration ./... -v -timeout 120s

vet:
	go vet ./...

lint:
	@if ! command -v golangci-lint &>/dev/null; then \
	  echo "Installing golangci-lint..."; \
	  go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
	fi
	golangci-lint run ./...

# ── Setup ─────────────────────────────────────────────────────────────────────

setup:
	@mkdir -p bin
	@if [ ! -f .env ]; then \
	  cp .env.example .env; \
	  echo "Created .env — fill in GEMINI_API_KEY before running"; \
	else \
	  echo ".env already exists, skipping"; \
	fi
	go mod download
	@echo "Go deps downloaded"
	@if [ -d $(WEB_DIR) ]; then \
	  cd $(WEB_DIR) && npm install; \
	  echo "Frontend deps installed"; \
	fi

# ── Docker ────────────────────────────────────────────────────────────────────

docker-up:
	docker compose up -d
	@echo "Waiting for services to be healthy..."
	@docker compose ps

docker-down:
	docker compose down
	@echo "Services stopped"

pull-models:
	@echo "Pulling Ollama models (nomic-embed-text ~274 MB)..."
	bash scripts/pull-models.sh

# ── Seed ──────────────────────────────────────────────────────────────────────

seed:
	@echo "Seeding POST /classify with 10 sample syslog events..."
	@for line in \
	  '<34>1 2024-01-15T10:30:00Z webserver01 sshd 1234 - Failed password for root from 192.168.1.100 port 22' \
	  '<34>1 2024-01-15T10:30:01Z webserver01 sshd 1234 - Failed password for root from 192.168.1.100 port 22' \
	  '<34>1 2024-01-15T10:30:02Z webserver01 sshd 1234 - Failed password for admin from 10.0.0.5 port 22' \
	  '<34>1 2024-01-15T10:31:00Z webserver01 nginx 5678 - GET /etc/passwd HTTP/1.1 200 0 "-" "-"' \
	  '<34>1 2024-01-15T10:31:05Z db01 postgres 9012 - FATAL: role "root" does not exist' \
	  '<34>1 2024-01-15T10:32:00Z appserver01 sudo 3456 - user: tty=pts/0 ; USER=root ; COMMAND=/bin/bash' \
	  '<34>1 2024-01-15T10:33:00Z firewall01 kernel 0 - DROP TCP 203.0.113.1:4444->10.0.1.5:80' \
	  '<34>1 2024-01-15T10:34:00Z workstation01 powershell 7890 - Invoke-Expression (New-Object Net.WebClient).DownloadString' \
	  '<34>1 2024-01-15T10:35:00Z webserver01 apache2 2345 - POST /login.php HTTP/1.1 200 - "sqlmap/1.6"' \
	  '<34>1 2024-01-15T10:36:00Z cron01 CRON 1111 - CMD (/usr/local/bin/backup.sh)' \
	  ; do \
	  curl -sf -X POST http://localhost:$(PORT)/classify \
	    -H "Content-Type: application/json" \
	    -d "{\"log\":\"$$line\",\"format\":\"syslog\"}" | python3 -m json.tool --no-ensure-ascii 2>/dev/null || true; \
	  echo "---"; \
	done

# ── Guard ─────────────────────────────────────────────────────────────────────

check-env:
	@if [ ! -f .env ]; then \
	  echo "ERROR: .env file not found. Run 'make setup' first."; exit 1; \
	fi
	@if [ -z "$$(grep -E '^(GEMINI|KIMCHI|OPENAI)_API_KEY=.+' .env 2>/dev/null)" ]; then \
	  echo "ERROR: set GEMINI_API_KEY (or KIMCHI_API_KEY) in .env"; exit 1; \
	fi

# ── Clean ─────────────────────────────────────────────────────────────────────

clean:
	rm -rf bin/
	@if [ -d $(WEB_DIR)/dist ]; then rm -rf $(WEB_DIR)/dist; fi
	@echo "Cleaned build artifacts"
