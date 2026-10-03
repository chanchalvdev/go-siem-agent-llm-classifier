package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	openai "github.com/sashabaranov/go-openai"
	"golang.org/x/time/rate"

	"github.com/chverma/siemagent/internal/agent"
	"github.com/chverma/siemagent/internal/classifier"
	"github.com/chverma/siemagent/internal/config"
	"github.com/chverma/siemagent/internal/detection"
	"github.com/chverma/siemagent/internal/incident"
	"github.com/chverma/siemagent/internal/metrics"
	"github.com/chverma/siemagent/internal/models"
	"github.com/chverma/siemagent/internal/parser"
	"github.com/chverma/siemagent/internal/store"
)

// SearchResult is a plain-Go hit returned by the vector store.
type SearchResult struct {
	ID      string
	Score   float32
	Payload map[string]any
}

// Searcher abstracts the Qdrant vector search so tests can inject a mock.
// severityFilter is an optional "P1"–"P5" string; empty means no filter.
type Searcher interface {
	Search(ctx context.Context, queryVector []float32, topK uint64, severityFilter string) ([]SearchResult, error)
}

// Embedder abstracts Ollama so tests can inject a mock.
type Embedder interface {
	Embed(ctx context.Context, text string) ([]float32, error)
}

type Server struct {
	cfg        config.Config
	classifier classifier.Interface
	parser     *parser.Parser
	router     *chi.Mux
	http       *http.Server
	events     store.Store
	search     Searcher          // nil when Qdrant not configured
	embed      Embedder          // nil when Ollama not configured
	hub        *Hub              // nil when live alert stream disabled
	agent      *agentRuntime     // nil when Phase 3 agent disabled
	detections *detection.Engine // nil when detection rules are off
	incidents  *incident.Service // nil when correlation is off
}

// maxConcurrentInvestigations caps agent runs in flight. Bulk ingest and
// syslog can produce bursts of P1/P2 events; without a cap each would start
// its own multi-call LLM investigation at once.
const maxConcurrentInvestigations = 4

// agentRuntime bundles the pieces the P1/P2 auto-trigger needs.
type agentRuntime struct {
	client   *openai.Client
	model    string
	registry *agent.Registry
	slots    chan struct{} // semaphore of maxConcurrentInvestigations

	mu      sync.Mutex
	running map[string]bool // incident IDs with an investigation in flight
}

// ServerOption lets callers attach optional Phase 2/3 components.
type ServerOption func(*Server)

// WithDetections exposes the loaded detection rules over the API.
func WithDetections(e *detection.Engine) ServerOption {
	return func(srv *Server) { srv.detections = e }
}

// WithStore replaces the default in-memory event store (e.g. with Postgres).
func WithStore(st store.Store) ServerOption {
	return func(srv *Server) { srv.events = st }
}

func WithSearch(s Searcher, e Embedder) ServerOption {
	return func(srv *Server) {
		srv.search = s
		srv.embed = e
	}
}

// WithAgent enables the live incident stream: high-severity classifications
// auto-launch an agent investigation broadcast over the hub.
func WithAgent(hub *Hub, client *openai.Client, model string, reg *agent.Registry) ServerOption {
	return func(srv *Server) {
		srv.hub = hub
		srv.agent = &agentRuntime{
			client: client, model: model, registry: reg,
			slots:   make(chan struct{}, maxConcurrentInvestigations),
			running: map[string]bool{},
		}
	}
}

func New(cfg config.Config, cls classifier.Interface, opts ...ServerOption) *Server {
	s := &Server{
		cfg:        cfg,
		classifier: cls,
		parser:     parser.New(),
		events:     store.New(),
	}
	for _, opt := range opts {
		opt(s)
	}
	s.applyRuleStates()
	s.router = s.buildRouter()
	s.http = &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: s.router,
	}
	return s
}

func (s *Server) buildRouter() *chi.Mux {
	r := chi.NewRouter()

	// Middleware stack. middleware.RealIP is deliberately absent: it trusts
	// client-supplied X-Forwarded-For headers, which would let anyone spoof
	// their IP past the rate limiter.
	r.Use(middleware.RequestID)
	r.Use(slogRequestLogger)
	r.Use(middleware.Recoverer)
	r.Use(newRateLimiter(100).middleware)
	r.Use(securityHeaders)
	r.Use(corsMiddleware(s.cfg))

	// Public: health probes and API docs.
	r.Get("/health", s.handleHealth)
	r.Get("/health/ready", s.handleReady)
	r.Get("/docs", s.handleDocsUI)
	r.Get("/docs/openapi.yaml", s.handleDocsSpec)

	// Everything else requires an API key when SIEM_API_KEYS is set.
	r.Group(func(r chi.Router) {
		r.Use(apiKeyAuth(s.cfg.APIKeys))

		r.Handle("/metrics", promhttp.Handler())

		r.Route("/api", func(r chi.Router) {
			r.Post("/classify", s.handleClassify)
			r.Post("/classify/stream", s.handleClassifyStream)
			r.Post("/ingest", s.handleIngest)
			r.Get("/events", s.handleEvents)
			r.Get("/detections/rules", s.handleDetectionRules)
			r.Patch("/detections/rules/{id}", s.handleUpdateDetectionRule)
			r.Get("/search", s.handleSearch)
			r.Get("/analytics/summary", s.handleAnalyticsSummary)

			r.Get("/incidents", s.handleListIncidents)
			r.Get("/incidents/stats", s.handleIncidentStats)
			r.Get("/incidents/{id}", s.handleGetIncident)
			r.Patch("/incidents/{id}", s.handleUpdateIncident)
			r.Post("/incidents/{id}/comments", s.handleAddComment)
			r.Post("/incidents/{id}/investigate", s.handleInvestigateIncident)
			r.Get("/incidents/{id}/report", s.handleIncidentReport)
			r.Post("/incidents/{id}/feedback", s.handleIncidentFeedback)
		})

		// Legacy top-level routes for backward compatibility
		r.Post("/classify", s.handleClassify)
		r.Post("/classify/stream", s.handleClassifyStream)

		// Live incident stream (WebSocket)
		r.Get("/ws/alerts", s.handleAlertStream)
	})

	return r
}

// HTTPServer returns the underlying *http.Server for graceful shutdown.
func (s *Server) HTTPServer() *http.Server { return s.http }

func (s *Server) Start() error {
	slog.Info("SIEMAgent HTTP server starting",
		"component", "api",
		"addr", s.http.Addr,
	)
	return s.http.ListenAndServe()
}

// --- Rate limiter ---

type limiterEntry struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

type ipRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*limiterEntry
	rps      float64
}

func newRateLimiter(rps float64) *ipRateLimiter {
	rl := &ipRateLimiter{
		limiters: make(map[string]*limiterEntry),
		rps:      rps,
	}
	go rl.cleanup()
	return rl
}

func (rl *ipRateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		cutoff := time.Now().Add(-5 * time.Minute)
		rl.mu.Lock()
		for ip, entry := range rl.limiters {
			if entry.lastSeen.Before(cutoff) {
				delete(rl.limiters, ip)
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *ipRateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	entry, ok := rl.limiters[ip]
	if !ok {
		entry = &limiterEntry{lim: rate.NewLimiter(rate.Limit(rl.rps), int(rl.rps))}
		rl.limiters[ip] = entry
	}
	entry.lastSeen = time.Now()
	return entry.lim
}

func (rl *ipRateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}
		if !rl.getLimiter(ip).Allow() {
			http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- Structured request logger ---

func slogRequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// chi's wrapper preserves http.Hijacker so WebSocket upgrades still work.
		rec := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(rec, r)
		status := rec.Status()
		if status == 0 {
			status = http.StatusOK
		}
		slog.Info("request",
			"component", "api",
			"method", r.Method,
			"path", r.URL.Path,
			"status", status,
			"latency_ms", time.Since(start).Milliseconds(),
			"request_id", middleware.GetReqID(r.Context()),
		)
	})
}

// --- Security headers ---

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// --- CORS middleware ---

func corsMiddleware(cfg config.Config) func(http.Handler) http.Handler {
	origin := cfg.AllowedOrigin
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if origin != "" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// --- Classify handler ---

func validateClassifyRequest(req *models.ClassifyRequest) *models.ValidationError {
	if req.Log == "" {
		return &models.ValidationError{Error: "log field is required", Field: "log"}
	}
	if len(req.Log) > 8192 {
		return &models.ValidationError{Error: "log field must not exceed 8192 bytes", Field: "log"}
	}
	if req.Format == "" {
		req.Format = "auto"
	}
	switch req.Format {
	case "syslog", "json", "auto":
	default:
		return &models.ValidationError{Error: "format must be one of: syslog, json, auto", Field: "format"}
	}
	return nil
}

func (s *Server) handleClassify(w http.ResponseWriter, r *http.Request) {
	var req models.ClassifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, models.ValidationError{Error: "invalid JSON body", Field: ""})
		return
	}
	if verr := validateClassifyRequest(&req); verr != nil {
		writeJSON(w, http.StatusBadRequest, verr)
		return
	}

	events := s.parser.ParseLineWithFormat(req.Log, req.Format)
	if len(events) == 0 {
		events = []models.LogEvent{s.parser.ParseRaw(req.Log)}
	}

	classified, err := s.classifier.Classify(r.Context(), events[0])
	if err != nil {
		slog.Error("classification failed", "component", "api", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	s.record(classified)
	writeJSON(w, http.StatusOK, sanitizeEvent(classified))
}

// record persists a classified event, correlates it into an incident and,
// for P1/P2, launches the incident agent. Every ingestion path (HTTP, stream,
// bulk, syslog) goes through here. It deliberately ignores the request
// context: a client disconnecting must not lose an event that was already
// classified.
func (s *Server) record(ev models.ClassifiedEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.events.Add(ctx, ev); err != nil {
		metrics.StoreErrorsTotal.Inc()
		slog.Error("persist event failed", "component", "api", "error", err)
	}
	if s.incidents == nil {
		s.maybeInvestigate(ev, uuid())
		return
	}
	res, ok := s.correlate(ev)
	if !ok {
		return
	}
	// Investigate once per incident, when it opens as P1/P2 or escalates
	// into P1/P2, rather than once per alert: a 500-event brute force must
	// not start 50 agent runs.
	if res.Created || res.Escalated {
		s.maybeInvestigate(ev, res.Incident.ID)
	}
}

// uuid returns a short random incident identifier (crypto/rand hex).
func uuid() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// --- SSE streaming classify handler ---

func (s *Server) handleClassifyStream(w http.ResponseWriter, r *http.Request) {
	var req models.ClassifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}
	if verr := validateClassifyRequest(&req); verr != nil {
		writeJSON(w, http.StatusBadRequest, verr)
		return
	}

	events := s.parser.ParseLineWithFormat(req.Log, req.Format)
	if len(events) == 0 {
		events = []models.LogEvent{s.parser.ParseRaw(req.Log)}
	}
	ev := events[0]

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	sendSSE := func(data any) {
		b, _ := json.Marshal(data)
		_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	classified, err := s.classifier.ClassifyStream(ctx, ev, func(chunk string) {
		sendSSE(map[string]string{"chunk": chunk})
	})
	if err != nil {
		sendSSE(map[string]string{"error": err.Error()})
		return
	}

	s.record(classified)
	sendSSE(map[string]interface{}{"result": sanitizeEvent(classified), "done": true})
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
