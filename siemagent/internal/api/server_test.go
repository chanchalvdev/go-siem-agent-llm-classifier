package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chverma/siemagent/internal/config"
	"github.com/chverma/siemagent/internal/models"
)

// mockClassifier implements classifier.Interface with a fixed response.
type mockClassifier struct {
	result models.ClassifiedEvent
	err    error
}

func (m *mockClassifier) Classify(_ context.Context, ev models.LogEvent) (models.ClassifiedEvent, error) {
	if m.err != nil {
		return models.ClassifiedEvent{}, m.err
	}
	m.result.Event = ev
	return m.result, nil
}

func (m *mockClassifier) ClassifyStream(_ context.Context, ev models.LogEvent, onChunk func(string)) (models.ClassifiedEvent, error) {
	if onChunk != nil {
		onChunk(`{"chunk":"test"}`)
	}
	return m.Classify(nil, ev) //nolint:staticcheck
}

func (m *mockClassifier) Ping(_ context.Context) error { return nil }

var fixedResult = models.ClassifiedEvent{
	AttackType: "Brute Force",
	Severity:   models.SeverityP2,
	MITRE: models.MITREInfo{
		Tactic:      "Credential Access",
		TechniqueID: "T1110.001",
		Technique:   "Password Guessing",
	},
	Confidence:  0.9,
	IOCs:        []string{"192.168.1.100"},
	Summary:     "SSH brute force attempt detected.",
	Remediation: "Block the source IP.",
	ProcessedAt: time.Now().UTC(),
}

func newTestServer() (*Server, *httptest.Server) {
	cfg := config.Config{Port: "0", AllowedOrigin: "http://localhost:5173"}
	mock := &mockClassifier{result: fixedResult}
	srv := New(cfg, mock)
	ts := httptest.NewServer(srv.router)
	return srv, ts
}

func TestHandleHealth_Returns200(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200, got %d", resp.StatusCode)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf(`body["status"]: want "ok", got %q`, body["status"])
	}
}

func TestHandleClassify_ValidSyslog(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	payload := `{"log":"<165>1 2024-01-15T10:30:00Z host sshd 1 - Failed password","format":"syslog"}`
	resp, err := http.Post(ts.URL+"/classify", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /classify: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200, got %d", resp.StatusCode)
	}

	var ev models.ClassifiedEvent
	if err := json.NewDecoder(resp.Body).Decode(&ev); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if ev.AttackType != fixedResult.AttackType {
		t.Errorf("AttackType: want %q, got %q", fixedResult.AttackType, ev.AttackType)
	}
	if ev.Severity != fixedResult.Severity {
		t.Errorf("Severity: want %q, got %q", fixedResult.Severity, ev.Severity)
	}
}

func TestHandleClassify_EmptyBody_Returns400(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	// Body with empty log field
	payload := `{"log":"","format":"auto"}`
	resp, err := http.Post(ts.URL+"/classify", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /classify: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: want 400, got %d", resp.StatusCode)
	}

	var verr models.ValidationError
	if err := json.NewDecoder(resp.Body).Decode(&verr); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if verr.Field != "log" {
		t.Errorf("error field: want %q, got %q", "log", verr.Field)
	}
}

func TestHandleClassify_OversizedBody_Returns400(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	// Build a log line > 8192 bytes
	bigLog := strings.Repeat("A", 8193)
	payload, _ := json.Marshal(map[string]string{"log": bigLog, "format": "auto"})

	resp, err := http.Post(ts.URL+"/classify", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /classify: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: want 400, got %d", resp.StatusCode)
	}

	var verr models.ValidationError
	if err := json.NewDecoder(resp.Body).Decode(&verr); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	if verr.Field != "log" {
		t.Errorf("error field: want %q, got %q", "log", verr.Field)
	}
}

func TestHandleClassify_InvalidFormat_Returns400(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	payload := `{"log":"some log line","format":"xml"}`
	resp, err := http.Post(ts.URL+"/classify", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /classify: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: want 400, got %d", resp.StatusCode)
	}
}

func TestHandleClassify_InvalidJSON_Returns400(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/classify", "application/json", strings.NewReader(`{bad json`))
	if err != nil {
		t.Fatalf("POST /classify: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: want 400, got %d", resp.StatusCode)
	}
}

// TestHandleClassify_ResponseFields verifies all required fields are present.
func TestHandleClassify_ResponseFields(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	payload := `{"log":"Failed login from 10.0.0.1","format":"auto"}`
	resp, err := http.Post(ts.URL+"/classify", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /classify: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var raw map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, field := range []string{"attack_type", "severity", "confidence", "iocs", "summary", "mitre", "event"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("response missing field %q", field)
		}
	}
}

func TestDocs_UIReturns200(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/docs")
	if err != nil {
		t.Fatalf("GET /docs: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type: want text/html, got %q", ct)
	}
}

func TestDocs_SpecReturnsYAML(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/docs/openapi.yaml")
	if err != nil {
		t.Fatalf("GET /docs/openapi.yaml: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status: want 200, got %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "yaml") {
		t.Errorf("Content-Type: want application/yaml, got %q", ct)
	}
}
