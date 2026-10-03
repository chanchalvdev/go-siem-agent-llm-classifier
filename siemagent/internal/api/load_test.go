package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chverma/siemagent/internal/config"
	"github.com/chverma/siemagent/internal/models"
)

// instantClassifier returns the fixed result with zero latency.
type instantClassifier struct{}

func (ic *instantClassifier) Classify(_ context.Context, ev models.LogEvent) (models.ClassifiedEvent, error) {
	return models.ClassifiedEvent{
		Event:      ev,
		AttackType: "Brute Force",
		Severity:   models.SeverityP3,
		IOCs:       []string{},
	}, nil
}

func (ic *instantClassifier) ClassifyStream(_ context.Context, ev models.LogEvent, _ func(string)) (models.ClassifiedEvent, error) {
	return ic.Classify(nil, ev) //nolint:staticcheck
}

func (ic *instantClassifier) Ping(_ context.Context) error { return nil }

func benchmarkServer() *httptest.Server {
	cfg := config.Config{Port: "0"}
	srv := New(cfg, &instantClassifier{})
	return httptest.NewServer(srv.router)
}

func BenchmarkClassifyEndpoint(b *testing.B) {
	ts := benchmarkServer()
	defer ts.Close()

	payload, _ := json.Marshal(map[string]string{
		"log":    "<165>1 2024-01-15T10:30:00Z webserver sshd 1 - Failed password for root from 192.168.1.100",
		"format": "syslog",
	})

	b.SetParallelism(10)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := http.Post(ts.URL+"/classify", "application/json", bytes.NewReader(payload))
			if err != nil {
				b.Errorf("POST /classify: %v", err)
				continue
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				b.Errorf("unexpected status %d", resp.StatusCode)
			}
		}
	})
}

func BenchmarkClassifyEndpoint_Sequential(b *testing.B) {
	ts := benchmarkServer()
	defer ts.Close()

	payload, _ := json.Marshal(map[string]string{
		"log":    "Failed login attempt from 10.0.0.1 user=admin",
		"format": "auto",
	})

	b.ResetTimer()
	for b.Loop() {
		resp, err := http.Post(ts.URL+"/classify", "application/json", bytes.NewReader(payload))
		if err != nil {
			b.Fatal(err)
		}
		_ = resp.Body.Close()
	}
}

func BenchmarkParseLogFile(b *testing.B) {
	// Build 1000 representative syslog lines in memory.
	lines := make([]string, 1000)
	for i := range lines {
		lines[i] = "<165>1 2024-01-15T10:30:00Z webserver sshd 1234 - Failed password for root from 192.168.1.100 port 22"
	}
	input := strings.Join(lines, "\n")

	cfg := config.Config{Port: "0"}
	srv := New(cfg, &instantClassifier{})

	b.ResetTimer()
	for b.Loop() {
		for _, line := range strings.Split(input, "\n") {
			srv.parser.ParseLine(line)
		}
	}
}

func BenchmarkValidateClassifyRequest(b *testing.B) {
	req := &models.ClassifyRequest{
		Log:    "<165>1 2024-01-15T10:30:00Z webserver sshd 1234 - Failed password for root",
		Format: "auto",
	}
	b.ResetTimer()
	for b.Loop() {
		validateClassifyRequest(req)
	}
}
