package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	openai "github.com/sashabaranov/go-openai"

	"github.com/chverma/siemagent/internal/models"
)

// validClassification is the JSON the mock LLM returns.
var validClassification = `{
  "attack_type": "Brute Force",
  "tactic": "Credential Access",
  "technique_id": "T1110.001",
  "technique": "Password Guessing",
  "severity": "P2",
  "confidence": 0.95,
  "iocs": ["192.168.1.100", "root"],
  "remediation": "Block the IP and reset the account.",
  "summary": "Multiple failed SSH login attempts from 192.168.1.100."
}`

// makeSSEServer returns a test HTTP server that streams the given content
// as an OpenAI-compatible chat completion SSE response.
func makeSSEServer(content string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		// Send content in a single chunk then a stop chunk
		chunks := []map[string]interface{}{
			{
				"id":     "chatcmpl-test",
				"object": "chat.completion.chunk",
				"model":  "test-model",
				"choices": []map[string]interface{}{
					{"index": 0, "delta": map[string]string{"role": "assistant", "content": content}, "finish_reason": nil},
				},
			},
			{
				"id":     "chatcmpl-test",
				"object": "chat.completion.chunk",
				"model":  "test-model",
				"choices": []map[string]interface{}{
					{"index": 0, "delta": map[string]string{}, "finish_reason": "stop"},
				},
			},
		}
		for _, chunk := range chunks {
			b, _ := json.Marshal(chunk)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
	}))
}

func newTestClassifier(srv *httptest.Server) *Classifier {
	cfg := openai.DefaultConfig("test-key")
	cfg.BaseURL = srv.URL + "/v1"
	return &Classifier{
		client: openai.NewClientWithConfig(cfg),
		model:  "test-model",
	}
}

func sampleEvent() models.LogEvent {
	return models.LogEvent{
		Raw:     `<165>1 2024-01-15T10:30:00Z webserver sshd 1234 - Failed password for root from 192.168.1.100`,
		Message: "Failed password for root from 192.168.1.100",
		Source:  "syslog",
	}
}

func TestClassify_ValidResponse(t *testing.T) {
	srv := makeSSEServer(validClassification)
	defer srv.Close()

	c := newTestClassifier(srv)
	ev, err := c.Classify(context.Background(), sampleEvent())
	if err != nil {
		t.Fatalf("Classify: unexpected error: %v", err)
	}

	if ev.AttackType != "Brute Force" {
		t.Errorf("AttackType: want %q, got %q", "Brute Force", ev.AttackType)
	}
	if ev.Severity != models.SeverityP2 {
		t.Errorf("Severity: want P2, got %q", ev.Severity)
	}
	if ev.MITRE.TechniqueID != "T1110.001" {
		t.Errorf("TechniqueID: want %q, got %q", "T1110.001", ev.MITRE.TechniqueID)
	}
	if ev.Confidence != 0.95 {
		t.Errorf("Confidence: want 0.95, got %f", ev.Confidence)
	}
}

func TestClassify_MarkdownFenceStripping(t *testing.T) {
	fenced := "```json\n" + validClassification + "\n```"
	srv := makeSSEServer(fenced)
	defer srv.Close()

	c := newTestClassifier(srv)
	ev, err := c.Classify(context.Background(), sampleEvent())
	if err != nil {
		t.Fatalf("Classify: unexpected error: %v", err)
	}
	if ev.AttackType != "Brute Force" {
		t.Errorf("AttackType after fence strip: want %q, got %q", "Brute Force", ev.AttackType)
	}
}

func TestClassify_MalformedJSON(t *testing.T) {
	srv := makeSSEServer(`{this is not json}`)
	defer srv.Close()

	c := newTestClassifier(srv)
	_, err := c.Classify(context.Background(), sampleEvent())
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
}

// TestUnmarshalLLM_FenceStripping tests the fence-stripping helper directly.
func TestUnmarshalLLM_FenceStripping(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"plain JSON", validClassification},
		{"json fence", "```json\n" + validClassification + "\n```"},
		{"plain fence", "```\n" + validClassification + "\n```"},
		// Leading prose before the JSON block (LLM sometimes adds a preamble)
		{"leading prose", "Here is the analysis:\n" + validClassification},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := unmarshalLLM(tc.input)
			if err != nil {
				t.Fatalf("unmarshalLLM: unexpected error: %v", err)
			}
			if a.AttackType != "Brute Force" {
				t.Errorf("AttackType: want %q, got %q", "Brute Force", a.AttackType)
			}
			if a.Severity != "P2" {
				t.Errorf("Severity: want P2, got %q", a.Severity)
			}
		})
	}
}

// TestUnmarshalLLM_SeverityNormalisation checks that unknown severities become P5.
func TestUnmarshalLLM_SeverityNormalisation(t *testing.T) {
	raw := `{"attack_type":"X","severity":"critical","confidence":0.5,"iocs":[]}`
	a, err := unmarshalLLM(raw)
	if err != nil {
		t.Fatalf("unmarshalLLM: %v", err)
	}
	if a.Severity != "P5" {
		t.Errorf("expected P5 normalisation for unknown severity, got %q", a.Severity)
	}
}
