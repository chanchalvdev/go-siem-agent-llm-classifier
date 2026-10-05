package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// LLM providers. Every provider is reached through an OpenAI-compatible
// endpoint, so the go-openai client works against all of them unchanged.
const (
	ProviderGemini = "gemini"
	ProviderOllama = "ollama" // local model, no API key, logs never leave the host
	ProviderOpenAI = "openai" // any OpenAI-compatible endpoint (Kimchi, OpenAI, Groq…)
	// ProviderNone runs rules only: no LLM classification or AI investigation.
	ProviderNone = "none"
)

const (
	geminiBaseURL = "https://generativelanguage.googleapis.com/v1beta/openai/"
	geminiModel   = "gemini-3.8-flash"
	ollamaModel   = "llama3.2"
	openaiBaseURL = "https://api.kimchi.ai/v1"
	openaiModel   = "kimi-k2-5"
)

type Config struct {
	Provider      string // ProviderGemini | ProviderOllama | ProviderOpenAI | ProviderNone
	BaseURL       string // OpenAI-compatible endpoint
	APIKey        string
	ModelName     string
	Workers       int
	Port          string
	QdrantAddr    string   // gRPC address for Qdrant (host:port)
	OllamaURL     string   // Ollama base URL (embeddings, and chat when Provider is ollama)
	AllowedOrigin string   // CORS allowed origin
	APIKeys       []string // accepted API keys; empty disables auth (dev mode)
	PostgresDSN   string   // empty keeps events in memory only
	SyslogUDPAddr string   // e.g. ":5514"; empty disables the UDP listener
	SyslogTCPAddr string   // e.g. ":5514"; empty disables the TCP listener
	DetectionMode string   // rules-first (default) | enrich | off
	SigmaRulesDir string   // extra Sigma rules, e.g. a SigmaHQ checkout

	// Incident correlation (see Incidents). Raw values; Validate checks them.
	IncidentWindowRaw      string // e.g. "1h"; default 1h
	IncidentMinSeverityRaw string // P1–P5; default P3

	// Response playbooks.
	PlaybooksDir       string // extra playbooks (.yml)
	ResponseWebhookURL string // receives block_ip / disable_user / isolate_host
	SlackWebhookURL    string // Slack incoming webhook for notify actions

	// User accounts.
	AdminUser     string // bootstrap admin, created only when no user exists
	AdminPassword string
	SessionTTLRaw string // e.g. "12h"
	CookieSecure  bool   // mark the session cookie Secure (behind a TLS proxy)

	// Data retention in days; empty or 0 keeps data forever. Raw values;
	// Validate checks them.
	RetentionEventsRaw    string // RETENTION_EVENTS_DAYS
	RetentionIncidentsRaw string // RETENTION_INCIDENTS_DAYS (resolved incidents)
	RetentionAuditRaw     string // RETENTION_AUDIT_DAYS

	// SeedLogFile is replayed through the pipeline on start when no events
	// are stored yet (demos); empty disables seeding.
	SeedLogFile string
}

// Retention is how long each kind of data is kept. Zero keeps it forever.
type Retention struct {
	Events    time.Duration
	Incidents time.Duration
	Audit     time.Duration
}

func Load() Config {
	ollamaURL := strings.TrimRight(getenv("OLLAMA_URL", "http://localhost:11434"), "/")

	cfg := Config{
		Workers:       5,
		Port:          getenv("CONDUCTOR_PORT", "8080"),
		QdrantAddr:    getenv("QDRANT_ADDR", "localhost:6334"),
		OllamaURL:     ollamaURL,
		AllowedOrigin: getenv("ALLOWED_ORIGIN", "http://localhost:5173"),
		APIKeys:       splitList(os.Getenv("SIEM_API_KEYS")),
		PostgresDSN:   os.Getenv("POSTGRES_DSN"),
		SyslogUDPAddr: os.Getenv("SYSLOG_UDP_ADDR"),
		SyslogTCPAddr: os.Getenv("SYSLOG_TCP_ADDR"),
		DetectionMode: strings.ToLower(strings.TrimSpace(os.Getenv("DETECTION_MODE"))),
		SigmaRulesDir: os.Getenv("SIGMA_RULES_DIR"),

		IncidentWindowRaw:      strings.TrimSpace(os.Getenv("INCIDENT_WINDOW")),
		IncidentMinSeverityRaw: strings.ToUpper(strings.TrimSpace(os.Getenv("INCIDENT_MIN_SEVERITY"))),

		PlaybooksDir:       os.Getenv("PLAYBOOKS_DIR"),
		ResponseWebhookURL: strings.TrimSpace(os.Getenv("RESPONSE_WEBHOOK_URL")),
		SlackWebhookURL:    strings.TrimSpace(os.Getenv("SLACK_WEBHOOK_URL")),

		AdminUser:     strings.TrimSpace(os.Getenv("SIEM_ADMIN_USER")),
		AdminPassword: os.Getenv("SIEM_ADMIN_PASSWORD"),
		SessionTTLRaw: strings.TrimSpace(os.Getenv("SIEM_SESSION_TTL")),
		CookieSecure:  parseBool(os.Getenv("SIEM_COOKIE_SECURE")),

		RetentionEventsRaw:    strings.TrimSpace(os.Getenv("RETENTION_EVENTS_DAYS")),
		RetentionIncidentsRaw: strings.TrimSpace(os.Getenv("RETENTION_INCIDENTS_DAYS")),
		RetentionAuditRaw:     strings.TrimSpace(os.Getenv("RETENTION_AUDIT_DAYS")),

		SeedLogFile: strings.TrimSpace(os.Getenv("SEED_LOG_FILE")),
	}

	cfg.Provider = strings.ToLower(strings.TrimSpace(os.Getenv("LLM_PROVIDER")))
	if cfg.Provider == "kimchi" {
		cfg.Provider = ProviderOpenAI
	}
	if cfg.Provider == "" {
		// Auto-detect: a Gemini key wins, otherwise the OpenAI-compatible fallback.
		cfg.Provider = ProviderOpenAI
		if os.Getenv("GEMINI_API_KEY") != "" {
			cfg.Provider = ProviderGemini
		}
	}

	// Each provider reads its own model variable so a leftover SIEM_MODEL
	// (e.g. a Kimchi model name) is never sent to Gemini or Ollama.
	switch cfg.Provider {
	case ProviderGemini:
		cfg.APIKey = os.Getenv("GEMINI_API_KEY")
		cfg.BaseURL = getenv("GEMINI_BASE_URL", geminiBaseURL)
		cfg.ModelName = getenv("GEMINI_MODEL", geminiModel)
	case ProviderOllama:
		// Ollama ignores the key, but the OpenAI client needs a non-empty one.
		cfg.APIKey = "ollama"
		cfg.BaseURL = ollamaURL + "/v1"
		cfg.ModelName = getenv("OLLAMA_MODEL", ollamaModel)
	case ProviderOpenAI:
		cfg.APIKey = os.Getenv("KIMCHI_API_KEY")
		if cfg.APIKey == "" {
			cfg.APIKey = os.Getenv("OPENAI_API_KEY")
		}
		cfg.BaseURL = getenv("KIMCHI_BASE_URL", openaiBaseURL)
		cfg.ModelName = getenv("SIEM_MODEL", openaiModel)
	}
	return cfg
}

// Incidents returns the correlation window and the least severe alert that
// joins an incident.
func (c Config) Incidents() (window time.Duration, minSeverity string, err error) {
	window, minSeverity = time.Hour, "P3"
	if c.IncidentWindowRaw != "" {
		d, err := time.ParseDuration(c.IncidentWindowRaw)
		if err != nil || d < time.Minute || d > 7*24*time.Hour {
			return 0, "", fmt.Errorf("INCIDENT_WINDOW %q must be a duration between 1m and 168h", c.IncidentWindowRaw)
		}
		window = d
	}
	if c.IncidentMinSeverityRaw != "" {
		switch c.IncidentMinSeverityRaw {
		case "P1", "P2", "P3", "P4", "P5":
			minSeverity = c.IncidentMinSeverityRaw
		default:
			return 0, "", fmt.Errorf("INCIDENT_MIN_SEVERITY %q must be P1–P5", c.IncidentMinSeverityRaw)
		}
	}
	return window, minSeverity, nil
}

// SessionTTL returns how long a dashboard login lasts (default 12h).
func (c Config) SessionTTL() (time.Duration, error) {
	if c.SessionTTLRaw == "" {
		return 12 * time.Hour, nil
	}
	d, err := time.ParseDuration(c.SessionTTLRaw)
	if err != nil || d < 5*time.Minute || d > 30*24*time.Hour {
		return 0, fmt.Errorf("SIEM_SESSION_TTL %q must be a duration between 5m and 720h", c.SessionTTLRaw)
	}
	return d, nil
}

// maxRetentionDays bounds retention settings (10 years).
const maxRetentionDays = 3650

// Retention returns the data retention policy.
func (c Config) Retention() (Retention, error) {
	var r Retention
	for _, f := range []struct {
		name string
		raw  string
		dst  *time.Duration
	}{
		{"RETENTION_EVENTS_DAYS", c.RetentionEventsRaw, &r.Events},
		{"RETENTION_INCIDENTS_DAYS", c.RetentionIncidentsRaw, &r.Incidents},
		{"RETENTION_AUDIT_DAYS", c.RetentionAuditRaw, &r.Audit},
	} {
		if f.raw == "" {
			continue
		}
		days, err := strconv.Atoi(f.raw)
		if err != nil || days < 0 || days > maxRetentionDays {
			return Retention{}, fmt.Errorf("%s %q must be a whole number of days between 0 (keep forever) and %d", f.name, f.raw, maxRetentionDays)
		}
		*f.dst = time.Duration(days) * 24 * time.Hour
	}
	return r, nil
}

// Validate reports configuration that would stop the agent from working.
func (c Config) Validate() error {
	if _, _, err := c.Incidents(); err != nil {
		return err
	}
	if _, err := c.SessionTTL(); err != nil {
		return err
	}
	if _, err := c.Retention(); err != nil {
		return err
	}
	if (c.AdminUser == "") != (c.AdminPassword == "") {
		return errors.New("set both SIEM_ADMIN_USER and SIEM_ADMIN_PASSWORD, or neither")
	}
	for name, v := range map[string]string{"RESPONSE_WEBHOOK_URL": c.ResponseWebhookURL, "SLACK_WEBHOOK_URL": c.SlackWebhookURL} {
		if v != "" && !strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "http://") {
			// Never echo the value: webhook URLs often embed a secret token.
			return fmt.Errorf("%s must be an http(s) URL", name)
		}
	}
	switch c.Provider {
	case ProviderGemini:
		if c.APIKey == "" {
			return errors.New("LLM_PROVIDER=gemini needs GEMINI_API_KEY")
		}
	case ProviderOpenAI:
		if c.APIKey == "" {
			return errors.New("set GEMINI_API_KEY, KIMCHI_API_KEY or OPENAI_API_KEY, or use LLM_PROVIDER=ollama for a local model")
		}
	case ProviderOllama:
	case ProviderNone:
		if c.DetectionMode != "" && c.DetectionMode != "rules-first" {
			return fmt.Errorf("LLM_PROVIDER=none needs DETECTION_MODE=rules-first (got %q): without an LLM only rules classify events", c.DetectionMode)
		}
	default:
		return fmt.Errorf("unknown LLM_PROVIDER %q (want gemini, ollama, openai or none)", c.Provider)
	}
	return nil
}

// AuthEnabled reports whether API key authentication is enforced.
func (c Config) AuthEnabled() bool { return len(c.APIKeys) > 0 }

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
