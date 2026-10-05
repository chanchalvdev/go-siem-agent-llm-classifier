package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Optional services that were never enabled must not make the server unready.
func TestReadyIgnoresDisabledOptionalServices(t *testing.T) {
	hc.mu.Lock()
	hc.expiresAt = time.Time{} // the result is cached process-wide
	hc.mu.Unlock()
	t.Cleanup(func() {
		hc.mu.Lock()
		hc.expiresAt = time.Time{}
		hc.mu.Unlock()
	})

	srv, _ := rulesOnlyServer(t)
	srv.cfg.QdrantAddr = "127.0.0.1:1" // configured but unreachable, so search was never enabled
	ts := httptest.NewServer(srv.router)
	defer ts.Close()

	var got struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	if code := doJSON(t, http.MethodGet, ts.URL+"/health/ready", "", &got); code != http.StatusOK || got.Status != "ready" {
		t.Fatalf("%d %+v", code, got)
	}
	if got.Checks["llm"] != "disabled" || got.Checks["qdrant"] != "disabled" {
		t.Fatalf("checks: %v", got.Checks)
	}
}
