package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chverma/siemagent/internal/config"
	"github.com/chverma/siemagent/internal/detection"
)

func getRules(t *testing.T, srv *Server) []detectionRule {
	t.Helper()
	ts := httptest.NewServer(srv.router)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/api/detections/rules")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var rules []detectionRule
	if err := json.NewDecoder(resp.Body).Decode(&rules); err != nil {
		t.Fatal(err)
	}
	return rules
}

func TestDetectionRulesEndpoint(t *testing.T) {
	rules, errs := detection.LoadBuiltin()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	engine, _ := detection.NewEngine(rules)
	srv := New(config.Config{Port: "0"}, &mockClassifier{result: fixedResult}, WithDetections(engine))

	got := getRules(t, srv)
	if len(got) != len(rules) {
		t.Fatalf("want %d rules, got %d", len(rules), len(got))
	}
	for _, r := range got {
		if r.ID == "" || r.Title == "" || r.Level == "" || r.Source != "builtin" {
			t.Fatalf("incomplete rule: %+v", r)
		}
	}
}

func TestDetectionRulesEndpointWithoutEngine(t *testing.T) {
	srv := New(config.Config{Port: "0"}, &mockClassifier{result: fixedResult})
	if got := getRules(t, srv); len(got) != 0 {
		t.Fatalf("no engine should list no rules, got %d", len(got))
	}
}
