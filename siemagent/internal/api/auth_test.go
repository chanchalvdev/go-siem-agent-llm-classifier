package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chverma/siemagent/internal/config"
)

func newAuthServer(t *testing.T, keys ...string) *httptest.Server {
	t.Helper()
	cfg := config.Config{Port: "0", APIKeys: keys}
	ts := httptest.NewServer(New(cfg, &mockClassifier{result: fixedResult}).router)
	t.Cleanup(ts.Close)
	return ts
}

func doGet(t *testing.T, url string, header map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestAuthDisabledWithoutKeys(t *testing.T) {
	ts := newAuthServer(t)
	if got := doGet(t, ts.URL+"/api/events", nil); got != http.StatusOK {
		t.Fatalf("without configured keys the API should be open, got %d", got)
	}
}

func TestAuthRequiresValidKey(t *testing.T) {
	ts := newAuthServer(t, "key-one", "key-two")

	cases := []struct {
		name   string
		path   string
		header map[string]string
		want   int
	}{
		{"no key", "/api/events", nil, http.StatusUnauthorized},
		{"wrong key", "/api/events", map[string]string{"X-API-Key": "nope"}, http.StatusUnauthorized},
		{"key prefix only", "/api/events", map[string]string{"X-API-Key": "key-"}, http.StatusUnauthorized},
		{"bearer", "/api/events", map[string]string{"Authorization": "Bearer key-one"}, http.StatusOK},
		{"x-api-key second key", "/api/events", map[string]string{"X-API-Key": "key-two"}, http.StatusOK},
		{"non-bearer scheme", "/api/events", map[string]string{"Authorization": "Basic key-one"}, http.StatusUnauthorized},
		{"query param on plain http", "/api/events?api_key=key-one", nil, http.StatusUnauthorized},
		{"metrics protected", "/metrics", nil, http.StatusUnauthorized},
		{"websocket protected", "/ws/alerts", nil, http.StatusUnauthorized},
		{"health public", "/health", nil, http.StatusOK},
		{"docs public", "/docs", nil, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := doGet(t, ts.URL+tc.path, tc.header); got != tc.want {
				t.Fatalf("GET %s: want %d, got %d", tc.path, tc.want, got)
			}
		})
	}
}

func TestAuthLegacyClassifyRouteProtected(t *testing.T) {
	ts := newAuthServer(t, "key-one")
	resp, err := http.Post(ts.URL+"/classify", "application/json", strings.NewReader(`{"log":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("legacy /classify must not bypass auth, got %d", resp.StatusCode)
	}
}

func TestRequestKeyWebSocketQueryParam(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ws/alerts?api_key=key-one", nil)
	if got := requestKey(req); got != "" {
		t.Fatalf("query key must be ignored without an upgrade, got %q", got)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	if got := requestKey(req); got != "key-one" {
		t.Fatalf("websocket upgrade should read api_key, got %q", got)
	}
}
