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
	"github.com/chverma/siemagent/internal/auth"
	"github.com/chverma/siemagent/internal/classifier"
	"github.com/chverma/siemagent/internal/config"
	"github.com/chverma/siemagent/internal/detection"
	"github.com/chverma/siemagent/internal/incident"
	"github.com/chverma/siemagent/internal/ingest"
	"github.com/chverma/siemagent/internal/ioc"
	"github.com/chverma/siemagent/internal/models"
	"github.com/chverma/siemagent/internal/parser"
	"github.com/chverma/siemagent/internal/pipeline"
	"github.com/chverma/siemagent/internal/response"
	"github.com/chverma/siemagent/internal/retention"
	"github.com/chverma/siemagent/internal/store"
	"github.com/chverma/siemagent/internal/suppression"
	"github.com/chverma/siemagent/pkg/ollama"
	pkgqdrant "github.com/chverma/siemagent/pkg/qdrant"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	var (
		serve     = flag.Bool("serve", false, "Start HTTP server mode")
		port      = flag.String("port", "", "HTTP server port (overrides $CONDUCTOR_PORT)")
		workers   = flag.Int("workers", 5, "Number of concurrent classifier goroutines")
		outFile   = flag.String("output", "", "Write JSON results to file instead of stdout")
		showVer   = flag.Bool("version", false, "Print the version and exit")
		migrateDB = flag.Bool("migrate", false, "Apply pending database migrations to $POSTGRES_DSN and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("siemagent", version)
		return
	}

	cfg := config.Load()
	if *migrateDB {
		if err := runMigrations(cfg.PostgresDSN); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}
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
	if cfg.Provider == config.ProviderNone {
		slog.Info("rules-only mode: events no rule matches are stored as Unclassified; AI investigation is off", "component", "main")
		return detection.NewClassifier(nil, engine, mode, cls.Index), engine
	}
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
		incStore, err := incident.NewPostgres(ctx, pg.Pool())
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		actStore, err := response.NewPostgres(ctx, pg.Pool())
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		authStore, err := auth.NewPostgres(ctx, pg.Pool())
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		supStore, err := suppression.NewPostgres(ctx, pg.Pool())
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		iocStore, err := ioc.NewPostgres(ctx, pg.Pool())
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		incidents := newIncidentService(cfg, incStore)
		opts = append(opts, api.WithIncidents(incidents), api.WithResponse(newResponseEngine(cfg, actStore, incidents)),
			api.WithUsers(newAuthService(ctx, cfg, authStore)), api.WithRetention(startRetention(ctx, cfg, pg)),
			api.WithSuppressions(newSuppressions(ctx, supStore)), api.WithWatchlists(startWatchlists(ctx, cfg, iocStore)))
	} else {
		slog.Warn("POSTGRES_DSN not set: events are kept in memory and lost on restart", "component", "main")
		if r, _ := cfg.Retention(); r != (config.Retention{}) {
			slog.Warn("RETENTION_* settings apply only with POSTGRES_DSN; ignoring them", "component", "main")
		}
		incidents := newIncidentService(cfg, incident.NewMemory())
		opts = append(opts, api.WithIncidents(incidents), api.WithResponse(newResponseEngine(cfg, response.NewMemory(), incidents)),
			api.WithUsers(newAuthService(ctx, cfg, auth.NewMemory())), api.WithSuppressions(newSuppressions(ctx, suppression.NewMemory())),
			api.WithWatchlists(startWatchlists(ctx, cfg, ioc.NewMemory())))
	}

	// Live incident stream: tool registry + WebSocket hub. Rules-only mode
	// has no LLM to investigate with.
	if cfg.Provider != config.ProviderNone {
		opts = append(opts, api.WithAgent(buildHub(), cls.OpenAIClient(), cfg.ModelName, reg))
	}

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

	if cfg.SeedLogFile != "" {
		go seed(ctx, srv, cfg.SeedLogFile)
	}

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

// newIncidentService builds alert correlation from validated configuration.
func newIncidentService(cfg config.Config, st incident.Store) *incident.Service {
	window, minSev, _ := cfg.Incidents() // checked by cfg.Validate at start
	slog.Info("incident correlation enabled", "component", "main", "window", window, "min_severity", minSev)
	return incident.NewService(st, incident.Config{Window: window, MinSeverity: models.Severity(minSev)})
}

// newAuthService opens the account store and creates the bootstrap admin.
// seed replays SEED_LOG_FILE once the server is up, if no events exist yet.
func seed(ctx context.Context, srv *api.Server, path string) {
	start := time.Now()
	n, err := srv.Seed(ctx, path)
	switch {
	case err != nil:
		slog.Error("seeding failed", "component", "main", "file", path, "error", err)
	case n == 0:
		slog.Info("seed skipped: events already stored", "component", "main", "file", path)
	default:
		slog.Info("seeded demo events", "component", "main", "file", path, "events", n,
			"duration_ms", time.Since(start).Milliseconds())
	}
}

// startWatchlists loads the IOC watchlists (stored lists and
// IOC_WATCHLIST_DIR) and keeps feeds refreshed until ctx ends. A list that
// cannot be loaded is fatal: silently matching nothing would hide attacks.
func startWatchlists(ctx context.Context, cfg config.Config, st ioc.Store) *ioc.Service {
	svc, err := ioc.NewService(ctx, st)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load watchlists: %v\n", err)
		os.Exit(1)
	}
	if cfg.WatchlistDir != "" {
		n, err := svc.LoadDir(cfg.WatchlistDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		slog.Info("watchlist files loaded", "component", "main", "dir", cfg.WatchlistDir, "lists", n)
	}
	total := 0
	for _, w := range svc.List() {
		total += w.Count
	}
	slog.Info("IOC watchlists ready", "component", "main", "lists", len(svc.List()), "indicators", total)
	go svc.Start(ctx) // downloads feeds now and when due
	return svc
}

// newSuppressions loads the alert suppressions; failing to read them is fatal
// because silently dropping every snooze would flood analysts.
func newSuppressions(ctx context.Context, st suppression.Store) *suppression.Service {
	svc, err := suppression.NewService(ctx, st)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load suppressions: %v\n", err)
		os.Exit(1)
	}
	if n := len(svc.List()); n > 0 {
		slog.Info("alert suppressions loaded", "component", "main", "count", n)
	}
	return svc
}

// startRetention runs the data retention policy in the background until ctx
// ends. Expired login sessions are purged even when no policy is set.
func startRetention(ctx context.Context, cfg config.Config, pg *store.Postgres) *retention.Runner {
	r, _ := cfg.Retention() // checked by cfg.Validate
	runner := retention.New(retention.Policy{Events: r.Events, Incidents: r.Incidents, Audit: r.Audit},
		retention.NewPostgres(pg.Pool()), time.Hour)
	if runner.Policy().Enabled() {
		slog.Info("data retention enabled", "component", "main", "events_days", int(r.Events.Hours()/24),
			"incidents_days", int(r.Incidents.Hours()/24), "audit_days", int(r.Audit.Hours()/24))
	} else {
		slog.Info("data retention off: events, incidents and audit entries are kept forever", "component", "main")
	}
	go runner.Start(ctx)
	return runner
}

func newAuthService(ctx context.Context, cfg config.Config, st auth.Store) *auth.Service {
	ttl, _ := cfg.SessionTTL() // checked by cfg.Validate at start
	svc, err := auth.NewService(ctx, st, ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	created, err := svc.Bootstrap(ctx, cfg.AdminUser, cfg.AdminPassword)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: bootstrap admin: %v\n", err)
		os.Exit(1)
	}
	if created {
		slog.Info("bootstrap admin created; remove SIEM_ADMIN_PASSWORD from the environment",
			"component", "main", "user", cfg.AdminUser)
	}
	switch {
	case svc.UsersEnabled():
		slog.Info("user accounts enabled: dashboard login required", "component", "main", "api_keys", len(cfg.APIKeys))
	case cfg.AuthEnabled():
		slog.Info("API key authentication only; set SIEM_ADMIN_USER/SIEM_ADMIN_PASSWORD for dashboard logins", "component", "main")
	default:
		slog.Warn("no API keys or user accounts: the API is open to anyone who can reach it", "component", "main")
	}
	return svc
}

// newResponseEngine loads built-in and PLAYBOOKS_DIR playbooks.
func newResponseEngine(cfg config.Config, st response.Store, incidents *incident.Service) *response.Engine {
	pbs, errs := response.LoadBuiltin()
	if cfg.PlaybooksDir != "" {
		more, moreErrs := response.LoadDir(cfg.PlaybooksDir)
		pbs = append(pbs, more...)
		errs = append(errs, moreErrs...)
	}
	exec := response.NewHTTPExecutor(response.Connectors{
		ContainmentURL: cfg.ResponseWebhookURL, SlackURL: cfg.SlackWebhookURL,
	})
	engine, dupErrs := response.NewEngine(pbs, st, exec, incidents)
	for _, e := range append(errs, dupErrs...) {
		slog.Warn("playbook skipped", "component", "main", "error", e)
	}
	slog.Info("response playbooks loaded", "component", "main", "playbooks", len(engine.Playbooks()),
		"containment_webhook", cfg.ResponseWebhookURL != "", "slack", cfg.SlackWebhookURL != "")
	return engine
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
