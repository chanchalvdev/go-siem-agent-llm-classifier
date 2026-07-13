package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/chverma/siemagent/internal/agent"
	"github.com/chverma/siemagent/internal/agent/tools"
	"github.com/chverma/siemagent/internal/api"
	"github.com/chverma/siemagent/internal/classifier"
	"github.com/chverma/siemagent/internal/config"
	"github.com/chverma/siemagent/internal/models"
	"github.com/chverma/siemagent/internal/parser"
	"github.com/chverma/siemagent/internal/pipeline"
	"github.com/chverma/siemagent/pkg/ollama"
	pkgqdrant "github.com/chverma/siemagent/pkg/qdrant"
)

func main() {
	var (
		serve   = flag.Bool("serve", false, "Start HTTP server mode")
		port    = flag.String("port", "", "HTTP server port (overrides $CONDUCTOR_PORT)")
		workers = flag.Int("workers", 5, "Number of concurrent classifier goroutines")
		outFile = flag.String("output", "", "Write JSON results to file instead of stdout")
	)
	flag.Parse()

	cfg := config.Load()
	if *port != "" {
		cfg.Port = *port
	}
	if *workers > 0 {
		cfg.Workers = *workers
	}

	if cfg.APIKey == "" {
		fmt.Fprintln(os.Stderr, "error: set KIMCHI_API_KEY (or OPENAI_API_KEY) before running")
		os.Exit(1)
	}

	cls := classifier.New(cfg.APIKey, cfg.BaseURL, cfg.ModelName)

	if *serve {
		runServer(cfg, cls)
		return
	}

	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: siemagent [flags] <logfile> [logfile...]")
		fmt.Fprintln(os.Stderr, "       siemagent --serve [--port 8080]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	out := os.Stdout
	if *outFile != "" {
		f, err := os.Create(*outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open output: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		out = f
	}

	runCLI(args, cfg, cls, out)
}

func runServer(cfg config.Config, cls *classifier.Classifier) {
	// Wire up Phase 2 RAG components (non-fatal if unavailable).
	embedder := ollama.NewEmbedder(cfg.OllamaURL)

	var opts []api.ServerOption
	reg := buildRegistry()
	qdrantStore, err := pkgqdrant.NewAPIStore(cfg.QdrantAddr, "siem_events")
	if err != nil {
		slog.Warn("Qdrant unavailable, semantic search disabled", "component", "main", "error", err)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = qdrantStore.EnsureCollection(ctx, 768)
		cancel()
		cls.WithIndexing(embedder, qdrantStore.Store)
		opts = append(opts, api.WithSearch(qdrantStore, embedder))
		// Give the agent recall over past events (only when the store is up).
		reg.Register(tools.NewSimilarEvents(embedder, qdrantSearchAdapter{qdrantStore}))
		slog.Info("Qdrant connected, semantic search enabled", "component", "main")
	}

	// Wire up Phase 3 agent: tool registry + live incident stream over WebSocket.
	opts = append(opts, api.WithAgent(buildHub(), cls.OpenAIClient(), cfg.ModelName, reg))

	srv := api.New(cfg, cls, opts...)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		slog.Info("shutting down", "component", "main")
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.HTTPServer().Shutdown(ctx); err != nil {
			slog.Error("shutdown error", "component", "main", "error", err)
		}
		slog.Info("shutdown complete", "component", "main")
	}()

	if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "server: %v\n", err)
		os.Exit(1)
	}
}

// buildHub creates the WebSocket hub for the live incident stream.
func buildHub() *api.Hub { return api.NewHub() }

// qdrantSearchAdapter adapts the Qdrant APIStore to tools.VectorSearcher so the
// similar-events agent tool stays decoupled from the api/qdrant packages.
type qdrantSearchAdapter struct{ store *pkgqdrant.APIStore }

func (q qdrantSearchAdapter) Search(ctx context.Context, vec []float32, topK uint64, sev string) ([]tools.SearchHit, error) {
	res, err := q.store.Search(ctx, vec, topK, sev)
	if err != nil {
		return nil, err
	}
	hits := make([]tools.SearchHit, len(res))
	for i, r := range res {
		hits[i] = tools.SearchHit{Score: r.Score, Payload: r.Payload}
	}
	return hits, nil
}

// buildRegistry assembles the Phase 3 tool registry. External-API tools read
// their keys from env and degrade gracefully when a key is absent.
func buildRegistry() *agent.Registry {
	reg := agent.New()
	reg.Register(tools.NewAbuseIPDB(os.Getenv("ABUSEIPDB_KEY"), nil))
	reg.Register(tools.NewOTX(os.Getenv("OTX_API_KEY"), nil))
	reg.Register(tools.MITRELookup{})
	slog.Info("agent tool registry ready", "component", "main", "tools", len(reg.All()))
	return reg
}

// --- CLI mode ---

type parseStats struct {
	syslog int
	json   int
	errors int
}

func runCLI(args []string, cfg config.Config, cls classifier.Interface, out *os.File) {
	p := parser.New()

	// Phase 1: Parse all events first so we know the total
	var events []models.LogEvent
	stats := parseStats{}
	for _, path := range args {
		evs, err := parseFile(path, p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
			stats.errors++
			continue
		}
		for _, ev := range evs {
			switch ev.Source {
			case "syslog":
				stats.syslog++
			case "json":
				stats.json++
			}
		}
		events = append(events, evs...)
	}

	total := len(events)
	fmt.Fprintf(os.Stderr, "Parsed %d events (%d syslog, %d json, %d errors)\n",
		total, stats.syslog, stats.json, stats.errors)

	if total == 0 {
		return
	}

	// Phase 2: Classify with progress bar
	pool := pipeline.NewWorkerPool(cfg.Workers, cls)
	results := pool.Start(context.Background())

	classified := make([]models.ClassifiedEvent, 0, total)
	done := make(chan struct{})
	go func() {
		defer close(done)
		count := 0
		for ev := range results {
			count++
			classified = append(classified, ev)
			printProgress(count, total, ev)
		}
		fmt.Fprintln(os.Stderr) // newline after progress bar
	}()

	for _, ev := range events {
		pool.Submit(ev)
	}
	pool.Close()
	<-done

	// Phase 3: Print summary table
	printSummaryTable(classified, out)
}

func parseFile(path string, p *parser.Parser) ([]models.LogEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var events []models.LogEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1<<20), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		events = append(events, p.ParseLine(line)...)
	}
	return events, scanner.Err()
}

func printProgress(done, total int, latest models.ClassifiedEvent) {
	const width = 20
	filled := (done * width) / total
	bar := strings.Repeat("■", filled) + strings.Repeat("□", width-filled)
	color := severityColor(latest.Severity)
	reset := "\033[0m"
	fmt.Fprintf(os.Stderr, "\r[%s] %d/%d classified — latest: %s%s %s%s   ",
		bar, done, total, color, latest.Severity, latest.AttackType, reset)
}

func severityColor(s models.Severity) string {
	switch s {
	case models.SeverityP1:
		return "\033[31m" // red
	case models.SeverityP2:
		return "\033[38;5;214m" // orange (256-color)
	case models.SeverityP3:
		return "\033[33m" // yellow
	case models.SeverityP4:
		return "\033[34m" // blue
	default:
		return "\033[90m" // grey
	}
}

type summaryKey struct {
	severity   models.Severity
	attackType string
}

func printSummaryTable(events []models.ClassifiedEvent, out *os.File) {
	counts := make(map[summaryKey]int)
	for _, ev := range events {
		counts[summaryKey{ev.Severity, ev.AttackType}]++
	}

	type row struct {
		summaryKey
		count int
	}
	rows := make([]row, 0, len(counts))
	for k, c := range counts {
		rows = append(rows, row{k, c})
	}

	severityOrder := map[models.Severity]int{
		models.SeverityP1: 1,
		models.SeverityP2: 2,
		models.SeverityP3: 3,
		models.SeverityP4: 4,
		models.SeverityP5: 5,
	}
	sort.Slice(rows, func(i, j int) bool {
		oi := severityOrder[rows[i].severity]
		oj := severityOrder[rows[j].severity]
		if oi != oj {
			return oi < oj
		}
		return rows[i].attackType < rows[j].attackType
	})

	reset := "\033[0m"
	fmt.Fprintln(out, "\nClassification Summary")
	fmt.Fprintln(out, strings.Repeat("─", 60))
	fmt.Fprintf(out, "%-10s %-30s %6s\n", "Severity", "Attack Type", "Count")
	fmt.Fprintln(out, strings.Repeat("─", 60))
	for _, r := range rows {
		color := severityColor(r.severity)
		fmt.Fprintf(out, "%s%-10s%s %-30s %6d\n",
			color, r.severity, reset, r.attackType, r.count)
	}
	fmt.Fprintln(out, strings.Repeat("─", 60))
}
