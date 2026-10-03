package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func input(t *testing.T, ip string) json.RawMessage {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"ip": ip})
	return b
}

func TestAbuseIPDBValidIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":87,"countryCode":"CN","isp":"Evil ISP","totalReports":142,"lastReportedAt":"2024-01-10T00:00:00Z"}}`))
	}))
	defer srv.Close()

	tool := NewAbuseIPDB("key", srv.Client())
	tool.baseURL = srv.URL

	out, err := tool.Execute(context.Background(), input(t, "8.8.8.8"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	for _, want := range []string{`"abuse_score":87`, `"country":"CN"`, `"total_reports":142`} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %s: %s", want, out)
		}
	}
}

func TestAbuseIPDBPrivateIPNoCall(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	tool := NewAbuseIPDB("key", srv.Client())
	tool.baseURL = srv.URL

	out, err := tool.Execute(context.Background(), input(t, "10.0.0.1"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("expected 0 upstream calls, got %d", hits.Load())
	}
	if !strings.Contains(out, "private IP") {
		t.Errorf("expected private-IP note, got %s", out)
	}
}

func TestAbuseIPDBUpstream429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	tool := NewAbuseIPDB("key", srv.Client())
	tool.baseURL = srv.URL

	if _, err := tool.Execute(context.Background(), input(t, "8.8.8.8")); err == nil {
		t.Fatal("expected error on 429")
	}
}

func TestAbuseIPDBMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{not json`))
	}))
	defer srv.Close()

	tool := NewAbuseIPDB("key", srv.Client())
	tool.baseURL = srv.URL

	if _, err := tool.Execute(context.Background(), input(t, "8.8.8.8")); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestAbuseIPDBMissingKey(t *testing.T) {
	tool := NewAbuseIPDB("", nil)
	out, err := tool.Execute(context.Background(), input(t, "8.8.8.8"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, "not set") {
		t.Errorf("expected missing-key note, got %s", out)
	}
}
