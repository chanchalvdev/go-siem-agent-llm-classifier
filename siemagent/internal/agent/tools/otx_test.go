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

func otxInput(indicator, typ string) json.RawMessage {
	b, _ := json.Marshal(map[string]string{"indicator": indicator, "type": typ})
	return b
}

func TestOTXValidIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"pulse_info":{"count":3,"pulses":[{"name":"APT Campaign","created":"2024-02-01","tags":["apt","malware"],"adversary":"APT28"}]}}`))
	}))
	defer srv.Close()

	tool := NewOTX("key", srv.Client())
	tool.baseURL = srv.URL

	out, err := tool.Execute(context.Background(), otxInput("8.8.8.8", "ip"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	for _, want := range []string{`"pulse_count":3`, "APT Campaign", "apt"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q: %s", want, out)
		}
	}
}

func TestOTXPrivateIPNoCall(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	tool := NewOTX("key", srv.Client())
	tool.baseURL = srv.URL

	out, err := tool.Execute(context.Background(), otxInput("192.168.1.5", "ip"))
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

func TestOTXUpstreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	tool := NewOTX("key", srv.Client())
	tool.baseURL = srv.URL

	if _, err := tool.Execute(context.Background(), otxInput("evil.com", "domain")); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestOTXBadType(t *testing.T) {
	tool := NewOTX("key", nil)
	if _, err := tool.Execute(context.Background(), otxInput("x", "url")); err == nil {
		t.Fatal("expected error on unsupported type")
	}
}

func TestOTXMissingKey(t *testing.T) {
	tool := NewOTX("", nil)
	out, err := tool.Execute(context.Background(), otxInput("8.8.8.8", "ip"))
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(out, "not set") {
		t.Errorf("expected missing-key note, got %s", out)
	}
}
