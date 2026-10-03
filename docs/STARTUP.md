# SIEM Agent — Server Startup Guide

## Prerequisites

Make sure the following are installed before starting:

- [Go 1.25+](https://go.dev/dl/)
- [Node.js 18+](https://nodejs.org/) (for the web frontend)
- [Docker + Docker Compose](https://docs.docker.com/get-docker/) (for Qdrant, Postgres, Ollama)
- A **Kimchi API key** (or OpenAI-compatible key)

---

## Step 1 — Clone and enter the project

```bash
cd siemagent
```

---

## Step 2 — Set up environment variables

```bash
cp .env.example .env
```

Open `.env` and fill in your API key:

```env
KIMCHI_API_KEY=your_kimchi_api_key_here   # required
KIMCHI_BASE_URL=https://api.kimchi.ai/v1  # default, change if using OpenAI
SIEM_MODEL=kimi-k2-5                      # LLM model to use
CONDUCTOR_PORT=8080                        # HTTP server port
```

> Alternatively, export the key directly: `export KIMCHI_API_KEY=your_key_here`

---

## Step 3 — Install dependencies

```bash
make setup
```

This will:
- Copy `.env.example` → `.env` (if `.env` doesn't exist yet)
- Download Go module dependencies (`go mod download`)
- Install frontend npm packages (`cd web && npm install`)
- Create the `bin/` directory

---

## Step 4 — Start supporting services (Docker)

Starts Qdrant (vector DB), Postgres, and Ollama in the background:

```bash
make docker-up
```

Verify all containers are healthy:

```bash
docker compose ps
```

---

## Step 5 — (Optional) Pull Ollama embedding models

Required only if you want semantic search / RAG features:

```bash
make pull-models
```

---

## Step 6 — Build the binary

```bash
make build
```

The compiled binary is written to `./bin/siemagent`.

---

## Step 7 — Start the HTTP server

```bash
make serve
```

This starts the server on the port set by `CONDUCTOR_PORT` (default `8080`).

To specify a port manually:

```bash
./bin/siemagent --serve --port 8080
```

The server is ready when you see output like:

```
INFO  server listening  addr=:8080
```

---

## Step 8 — Verify the server is running

```bash
curl http://localhost:8080/health
```

Expected response:

```json
{"status":"ok"}
```

---

## Step 9 — (Optional) Seed with sample log events

Sends 10 sample syslog lines to the `/classify` endpoint:

```bash
make seed
```

---

## Step 10 — Open the web UI

Visit in your browser:

```
http://localhost:8080
```

---

## Development Mode (live reload)

Runs both the Go server (with air for hot reload) and the Vite frontend dev server in parallel:

```bash
make dev
```

Frontend dev server runs at `http://localhost:5173`.

---

## CLI Mode (classify a log file directly)

Instead of running the HTTP server, classify a log file and print a summary table:

```bash
./bin/siemagent sample.log
```

Write results to a file:

```bash
./bin/siemagent --output results.json sample.log
```

---

## Stop all services

```bash
make docker-down
```

---

## Quick Reference

| Command             | Description                              |
|---------------------|------------------------------------------|
| `make setup`        | Install all dependencies                 |
| `make docker-up`    | Start Qdrant, Postgres, Ollama           |
| `make build`        | Compile the Go binary                    |
| `make serve`        | Start the HTTP server                    |
| `make dev`          | Start server + frontend with live reload |
| `make seed`         | Send sample logs to /classify            |
| `make test`         | Run all unit tests                       |
| `make docker-down`  | Stop all Docker services                 |
| `make clean`        | Remove build artifacts                   |
