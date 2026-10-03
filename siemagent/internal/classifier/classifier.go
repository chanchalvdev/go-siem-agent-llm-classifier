package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	openai "github.com/sashabaranov/go-openai"

	"github.com/chverma/siemagent/internal/metrics"
	"github.com/chverma/siemagent/internal/models"
)

const systemPrompt = `You are an expert security analyst and SIEM (Security Information and Event Management) system.

Analyze the provided security log event and return a JSON object with EXACTLY these fields:

{
  "attack_type": "string — human-readable attack category (e.g. Brute Force, SQL Injection, Privilege Escalation, Port Scan, Malware Execution, Lateral Movement, Data Exfiltration, Phishing, DDoS, Credential Dumping, or 'Benign' if not an attack)",
  "tactic": "string — MITRE ATT&CK tactic name (e.g. Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact) or 'N/A' if benign",
  "technique_id": "string — MITRE ATT&CK technique ID (e.g. T1110.001) or 'N/A'",
  "technique": "string — MITRE ATT&CK technique name (e.g. Brute Force: Password Guessing) or 'N/A'",
  "severity": "string — one of: P1 (Critical), P2 (High), P3 (Medium), P4 (Low), P5 (Informational)",
  "confidence": number — float 0.0-1.0 representing your confidence in this classification,
  "iocs": ["array", "of", "strings"] — Indicators of Compromise extracted: IP addresses, domains, file hashes, usernames, file paths. Empty array if none.,
  "remediation": "string — concrete, actionable remediation steps (2-3 sentences)",
  "summary": "string — one-sentence human-readable summary of what happened"
}

Rules:
- Respond with ONLY the JSON object, no markdown fences, no explanations.
- IOCs must be concrete values extracted from the log (e.g. "192.168.1.100", "malware.exe", "root").
- Severity guide: P1=active breach/ransomware/data exfil, P2=successful intrusion/priv esc, P3=failed attack attempt/anomaly, P4=policy violation/recon, P5=normal ops/noise.
- If the log is benign (e.g. routine cron job, normal auth success), set attack_type="Benign", tactic="N/A", technique_id="N/A", severity="P5".`

var jsonBlockRE = regexp.MustCompile(`(?s)\{.*\}`)

// Interface allows mocking in tests.
type Interface interface {
	Classify(ctx context.Context, ev models.LogEvent) (models.ClassifiedEvent, error)
	ClassifyStream(ctx context.Context, ev models.LogEvent, onChunk func(string)) (models.ClassifiedEvent, error)
	Ping(ctx context.Context) error
}

// Indexer is implemented by the Qdrant store; kept as an interface so Phase 1
// tests that don't wire Qdrant still compile and pass.
type Indexer interface {
	Upsert(ctx context.Context, id string, vector []float32, payload map[string]any) error
}

// VectorEmbedder is implemented by the Ollama client.
type VectorEmbedder interface {
	Embed(ctx context.Context, text string) ([]float32, error)
}

type Classifier struct {
	client   *openai.Client
	model    string
	embedder VectorEmbedder // optional; nil = no indexing
	indexer  Indexer        // optional; nil = no indexing
}

func New(apiKey, baseURL, model string) *Classifier {
	cfg := openai.DefaultConfig(apiKey)
	cfg.BaseURL = baseURL
	return &Classifier{
		client: openai.NewClientWithConfig(cfg),
		model:  model,
	}
}

// WithIndexing wires optional Qdrant embedding+indexing into the classifier.
func (c *Classifier) WithIndexing(embedder VectorEmbedder, indexer Indexer) {
	c.embedder = embedder
	c.indexer = indexer
}

// OpenAIClient exposes the underlying LLM client so the Phase 3 agent can reuse
// the same configured connection (DRY — one client, one endpoint).
func (c *Classifier) OpenAIClient() *openai.Client { return c.client }

// Ping sends a minimal request to verify the LLM is reachable.
func (c *Classifier) Ping(ctx context.Context) error {
	_, err := c.client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model: c.model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleUser, Content: "ping"},
		},
		MaxTokens: 1,
	})
	return err
}

// Classify classifies a log event using the LLM, recording Prometheus metrics.
func (c *Classifier) Classify(ctx context.Context, ev models.LogEvent) (models.ClassifiedEvent, error) {
	return c.ClassifyStream(ctx, ev, nil)
}

// ClassifyStream streams the LLM response, calling onChunk for each text delta.
// If onChunk is nil it is ignored.
func (c *Classifier) ClassifyStream(ctx context.Context, ev models.LogEvent, onChunk func(string)) (models.ClassifiedEvent, error) {
	start := time.Now()
	userMsg := buildUserMessage(ev)

	stream, err := c.client.CreateChatCompletionStream(ctx, openai.ChatCompletionRequest{
		Model: c.model,
		Messages: []openai.ChatCompletionMessage{
			{Role: openai.ChatMessageRoleSystem, Content: systemPrompt},
			{Role: openai.ChatMessageRoleUser, Content: userMsg},
		},
		Temperature: 0.1,
	})
	if err != nil {
		metrics.LLMStreamErrorsTotal.Inc()
		return models.ClassifiedEvent{}, fmt.Errorf("stream open: %w", err)
	}
	defer func() { _ = stream.Close() }()

	var sb strings.Builder
	for {
		chunk, err := stream.Recv()
		if err != nil {
			break
		}
		if len(chunk.Choices) > 0 {
			text := chunk.Choices[0].Delta.Content
			if text != "" {
				if onChunk != nil {
					onChunk(text)
				}
				sb.WriteString(text)
			}
		}
	}

	elapsed := time.Since(start).Seconds()
	metrics.ClassificationDurationSeconds.Observe(elapsed)

	raw := sb.String()
	analysis, err := unmarshalLLM(raw)
	if err != nil {
		return models.ClassifiedEvent{}, fmt.Errorf("parse LLM response: %w (raw: %.200s)", err, raw)
	}

	result := buildClassifiedEvent(ev, analysis)
	metrics.EventsClassifiedTotal.WithLabelValues(string(result.Severity), result.AttackType).Inc()

	// Asynchronously embed and index into Qdrant — does not block the response.
	if c.embedder != nil && c.indexer != nil {
		go c.indexEvent(result)
	}

	return result, nil
}

// Index stores an event produced elsewhere (e.g. by detection rules) for
// semantic search, asynchronously. No-op when indexing is not configured.
func (c *Classifier) Index(ev models.ClassifiedEvent) {
	if c.embedder != nil && c.indexer != nil {
		go c.indexEvent(ev)
	}
}

func (c *Classifier) indexEvent(ev models.ClassifiedEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	text := fmt.Sprintf("%s %s %s %s %s",
		ev.Event.Source, ev.Event.AppName, ev.Event.Message,
		ev.AttackType, ev.MITRE.Tactic)

	vec, err := c.embedder.Embed(ctx, text)
	if err != nil {
		slog.Warn("embed failed", "component", "classifier", "error", err)
		return
	}

	payload := map[string]any{
		"event_id":     ev.Event.Raw[:min(32, len(ev.Event.Raw))],
		"timestamp":    ev.ProcessedAt.Format(time.RFC3339),
		"source":       ev.Event.Source,
		"hostname":     ev.Event.Hostname,
		"attack_type":  ev.AttackType,
		"severity":     string(ev.Severity),
		"summary":      ev.Summary,
		"mitre_tactic": ev.MITRE.Tactic,
	}

	id := fmt.Sprintf("%s-%d", ev.Event.Raw[:min(16, len(ev.Event.Raw))], ev.ProcessedAt.UnixNano())
	if err := c.indexer.Upsert(ctx, id, vec, payload); err != nil {
		slog.Warn("qdrant upsert failed", "component", "classifier", "error", err)
	}
}

func buildUserMessage(ev models.LogEvent) string {
	var sb strings.Builder
	sb.WriteString("Analyze this security log event:\n\n")
	if ev.Source != "raw" {
		fmt.Fprintf(&sb, "Source: %s\n", ev.Source)
		if !ev.Timestamp.IsZero() {
			fmt.Fprintf(&sb, "Timestamp: %s\n", ev.Timestamp.Format(time.RFC3339))
		}
		if ev.Hostname != "" {
			fmt.Fprintf(&sb, "Hostname: %s\n", ev.Hostname)
		}
		if ev.AppName != "" {
			fmt.Fprintf(&sb, "Application: %s\n", ev.AppName)
		}
		if ev.ProcID != "" {
			fmt.Fprintf(&sb, "PID: %s\n", ev.ProcID)
		}
		fmt.Fprintf(&sb, "Message: %s\n", ev.Message)
		sb.WriteString("\nRaw log line:\n")
	}
	sb.WriteString(ev.Raw)
	return sb.String()
}

func unmarshalLLM(raw string) (models.LLMAnalysis, error) {
	raw = strings.TrimSpace(raw)

	// Strip markdown code fences
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	raw = strings.TrimSpace(raw)

	if !strings.HasPrefix(raw, "{") {
		if m := jsonBlockRE.FindString(raw); m != "" {
			raw = m
		}
	}

	var a models.LLMAnalysis
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		return models.LLMAnalysis{}, err
	}

	a.Severity = strings.ToUpper(strings.TrimSpace(a.Severity))
	switch a.Severity {
	case "P1", "P2", "P3", "P4", "P5":
	default:
		a.Severity = "P5"
	}

	if a.IOCs == nil {
		a.IOCs = []string{}
	}
	return a, nil
}

func buildClassifiedEvent(ev models.LogEvent, a models.LLMAnalysis) models.ClassifiedEvent {
	return models.ClassifiedEvent{
		Event:      ev,
		AttackType: a.AttackType,
		MITRE: models.MITREInfo{
			Tactic:      a.Tactic,
			TechniqueID: a.TechniqueID,
			Technique:   a.Technique,
		},
		Severity:     models.Severity(a.Severity),
		ClassifiedBy: models.ClassifiedByLLM,
		Confidence:   a.Confidence,
		IOCs:         a.IOCs,
		Remediation:  a.Remediation,
		Summary:      a.Summary,
		ProcessedAt:  time.Now().UTC(),
	}
}
