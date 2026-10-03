# Contributing

Thanks for helping build an open-source AI SOC platform. This guide covers
how to get a working setup, what a good change looks like, and how to send it.

## Ground rules

- **Discuss big changes first.** Open an issue before starting a new module,
  an API change or anything on the [roadmap](ROADMAP.md), so effort isn't wasted.
- **Security bugs go private.** Never open a public issue for a vulnerability;
  follow [SECURITY.md](SECURITY.md).
- **Never commit secrets.** `.env` is git-ignored; only `.env.example` with
  placeholders belongs in the repo.
- Be respectful. This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

You need Go 1.25+, Node.js 22+ and Docker.

```bash
git clone https://github.com/chanchalvdev/go-siem-agent-llm-classifier.git
cd go-siem-agent-llm-classifier
make setup          # .env from the template, Go + npm dependencies
make docker-up      # Postgres, Qdrant, Ollama
make dev            # backend :8080 + dashboard :5173
```

Set an LLM in `siemagent/.env`: `GEMINI_API_KEY`, or `LLM_PROVIDER=ollama` to
run fully locally without any key.

## Before you open a pull request

Run the same checks CI runs, from the repository root:

```bash
make quality-gate       # gofmt, vet, golangci-lint, race tests, build, web lint/types/tests/build
make test-integration   # Postgres + Qdrant tests (after make docker-up)
```

A pull request is ready when:

- `make quality-gate` passes.
- New behaviour has tests. Every Go package needs a `_test.go`; every React
  component needs a test in `siemagent/web/src/__tests__/`.
- Go uses `log/slog` (no `fmt.Println` in production paths) and new Prometheus
  metrics live in `internal/metrics`.
- Web server state goes through TanStack Query; no `console.log` in components.
- Docs and `.env.example` are updated when you add configuration.

## Pull requests

- Branch from `master`. Name the PR `feature/<short-name>` for features or
  `fix/<short-name>` for fixes.
- Use [Conventional Commits](https://www.conventionalcommits.org/) for commit
  messages (`feat:`, `fix:`, `docs:`, `ci:` …).
- Keep a PR to one logical change and describe what you tested.

## Where to start

Issues labelled `good first issue` are small and well defined. New detection
content, parsers for more log formats and integrations with other security
tools are always welcome — see the [roadmap](ROADMAP.md).
