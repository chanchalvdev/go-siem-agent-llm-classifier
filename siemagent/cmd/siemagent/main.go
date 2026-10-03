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
	"github.com/chverma/siemagent/internal/detection"
	"github.com/chverma/siemagent/internal/ingest"
	"github.com/chverma/siemagent/internal/models"
	"github.com/chverma/siemagent/internal/parser"
	"github.com/chverma/siemagent/internal/pipeline"
	"github.com/chverma/siemagent/internal/store"
	"github.com/chverma/siemagent/pkg/ollama"
	pkgqdrant "github.com/chverma/siemagent/pkg/qdrant"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	var (
		serve   = flag.Bool("serve", false, "Start HTTP server mode")
		port    = flag.String("port", "", "HTTP server port (overrides $CONDUCTOR_PORT)")
		workers = flag.Int("workers", 5, "Number of concurrent classifier goroutines")
		outFile = flag.String("output", "", "Write JSON results to file instead of stdout")
		showVer = flag.Bool("version", false, "Print the version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("siemagent", version)
		return
	}

	cfg := config.Load()
	if *port != "" {
		cfg.Port = *port
	}
	if *workers > 0 {
		cfg.Workers = *workers
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	slog.Info("LLM provider configured", "component", "main", "version", version, "provider", cfg.Provider, "model", cfg.ModelName)
	cls := classifier.New(cfg.APIKey, cfg.BaseURL, cfg.ModelName)
	detCls, engine := buildDetection(cfg, cls)

	if *serve {
		runServer(cfg, cls, detCls, engine)
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
		out = f
	}

	runCLI(args, cfg, detCls, out)

	// A failed close on a written file can mean lost results, so report it.
	if out != os.Stdout {
		if err := out.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "write output: %v\n", err)
			os.Exit(1)
		}
	}
}

// buildDetection loads detection rules and wraps the LLM classifier with them.
// It returns the classifier every ingestion path should use, and the engine
// (nil when DETECTION_MODE=off).
func buildDetection(cfg config.Config, cls *classifier.Classifier) (classifier.Interface, *detection.Engine) {
	mode, err := detection.ParseMode(cfg.DetectionMode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if mode == detection.ModeOff {
		slog.Info("detection rules disabled", "component", "main")
		return cls, nil
	}

	rules, errs := detection.LoadBuiltin()
	if cfg.SigmaRulesDir != "" {
		more, moreErrs := detection.LoadDir(cfg.SigmaRulesDir)
		rules = append(rules, more...)
		errs = append(errs, moreErrs...)
	}
	engine, dupErrs := detection.NewEngine(rules)
	errs = append(errs, dupErrs...)

	unsupported := 0
	for _, e := range errs {
		if errors.Is(e, detection.ErrUnsupported) {
			unsupported++ // expected for SigmaHQ aggregation/correlation rules
			continue
		}
		slog.Warn("detection rule skipped", "component", "main", "error", e)
	}
	slog.Info("detection rules loaded", "component", "main", "mode", mode,
		"rules", len(engine.Rules()), "skipped_unsupported", unsupported)
	return detection.NewClassifier(cls, engine, mode, cls.Index), engine
}

func runServer(cfg config.Config, cls *classifier.Classifier, detCls classifier.Interface, engine *detection.Engine) {
	// ctx is cancelled on SIGINT/SIGTERM and drives every shutdown below.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	embedder := ollama.NewEmbedder(cfg.OllamaURL)

	var opts []api.ServerOption
	reg := buildRegistry()

	// Semantic search needs Qdrant. The client connects lazily, so creating it
	// succeeds even when Qdrant is down: only a working EnsureCollection
	// proves the store is reachable.
	if qdrantStore, err := connectQdrant(ctx, cfg.QdrantAddr); err != nil {
		slog.Warn("Qdrant unavailable, semantic search disabled", "component", "main", "error", err)
	} else {
		cls.WithIndexing(embedder, qdrantStore.Store)
		opts = append(opts, api.WithSearch(qdrantStore, embedder))
		// Give the agent recall over past events (only when the store is up).
		reg.Register(tools.NewSimilarEvents(embedder, qdrantSearchAdapter{qdrantStore}))
		slog.Info("Qdrant connected, semantic search enabled", "component", "main")
	}

	// Durable event storage. Without Postgres events live in memory and are
	// lost on restart, so a configured-but-unreachable database is fatal
	// rather than a silent downgrade.
	if cfg.PostgresDSN != "" {
		dbCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		pg, err := store.OpenPostgres(dbCtx, cfg.PostgresDSN)
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		defer pg.Close()
		opts = append(opts, api.WithStore(pg))
		slog.Info("events persisted to Postgres", "component", "main")
	} else {
		slog.Warn("POSTGRES_DSN not set: events are kept in memory and lost on restart", "component", "main")
	}

	if !cfg.AuthEnabled() {
		slog.Warn("SIEM_API_KEYS not set: the API is open to anyone who can reach it", "component", "main")
	}

	// Live incident stream: tool registry + WebSocket hub.
	opts = append(opts, api.WithAgent(buildHub(), cls.OpenAIClient(), cfg.ModelName, reg))

	if engine != nil {
		opts = append(opts, api.WithDetections(engine))
	}

	srv := api.New(cfg, detCls, opts...)

	// Network log ingestion (syslog over UDP/TCP).
	var live *api.LiveIngest
	var syslogListener *ingest.SyslogListener
	if cfg.SyslogUDPAddr != "" || cfg.SyslogTCPAddr != "" {
		// Workers share ctx so shutdown cancels in-flight LLM calls instead of
		// waiting for a full queue to drain.
		live = srv.StartLiveIngest(ctx)
		l, err := ingest.ListenSyslog(ctx, cfg.SyslogUDPAddr, cfg.SyslogTCPAddr,
			func(transport, line string) { live.Submit(transport, line) })
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		syslogListener = l
		slog.Info("syslog listener started", "component", "main",
			"udp", cfg.SyslogUDPAddr, "tcp", cfg.SyslogTCPAddr)
	}

	go func() {
		<-ctx.Done()
		slog.Info("shutting down", "component", "main")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.HTTPServer().Shutdown(shutdownCtx); err != nil {
			slog.Error("shutdown error", "component", "main", "error", err)
		}
	}()

	if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "server: %v\n", err)
		os.Exit(1)
	}

	// Stop accepting syslog, then wait for the workers to exit.
	if syslogListener != nil {
		syslogListener.Wait()
		live.Close()
	}
	slog.Info("shutdown complete", "component", "main")
}

// connectQdrant returns a search store only when Qdrant actually answers.
func connectQdrant(ctx context.Context, addr string) (*pkgqdrant.APIStore, error) {
	qs, err := pkgqdrant.NewAPIStore(addr, "siem_events")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := qs.EnsureCollection(ctx, 768); err != nil {
		return nil, fmt.Errorf("ensure collection: %w", err)
	}
	return qs, nil
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
	defer func() { _ = f.Close() }()

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
	_, _ = fmt.Fprintln(out, "\nClassification Summary")
	_, _ = fmt.Fprintln(out, strings.Repeat("─", 60))
	_, _ = fmt.Fprintf(out, "%-10s %-30s %6s\n", "Severity", "Attack Type", "Count")
	_, _ = fmt.Fprintln(out, strings.Repeat("─", 60))
	for _, r := range rows {
		color := severityColor(r.severity)
		_, _ = fmt.Fprintf(out, "%s%-10s%s %-30s %6d\n",
			color, r.severity, reset, r.attackType, r.count)
	}
	_, _ = fmt.Fprintln(out, strings.Repeat("─", 60))
}
