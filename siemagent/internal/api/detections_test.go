package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chverma/siemagent/internal/config"
	"github.com/chverma/siemagent/internal/detection"
	"github.com/chverma/siemagent/internal/store"
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

func patchRule(t *testing.T, ts *httptest.Server, id, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/detections/rules/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func TestUpdateDetectionRule(t *testing.T) {
	rules, _ := detection.LoadBuiltin()
	engine, _ := detection.NewEngine(rules)
	st := store.New()
	srv := New(config.Config{Port: "0"}, &mockClassifier{result: fixedResult}, WithDetections(engine), WithStore(st))
	ts := httptest.NewServer(srv.router)
	defer ts.Close()

	id := rules[0].ID
	resp := patchRule(t, ts, id, `{"enabled": false}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var got detectionRule
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil || got.Enabled {
		t.Fatalf("rule should come back disabled: %+v %v", got, err)
	}
	if r, _ := engine.Rule(id); r.Enabled() {
		t.Fatal("engine rule still enabled")
	}
	states, _ := st.RuleStates(context.Background())
	if enabled, ok := states[id]; !ok || enabled {
		t.Fatalf("state not persisted: %v", states)
	}

	// A restarted server restores the saved state.
	engine2, _ := detection.NewEngine(func() []*detection.Rule { r, _ := detection.LoadBuiltin(); return r }())
	New(config.Config{Port: "0"}, &mockClassifier{result: fixedResult}, WithDetections(engine2), WithStore(st))
	if r, _ := engine2.Rule(id); r.Enabled() {
		t.Fatal("saved state not applied at start")
	}

	if resp := patchRule(t, ts, "no-such-rule", `{"enabled": true}`); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown rule: status %d", resp.StatusCode)
	}
	if resp := patchRule(t, ts, id, `{}`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing enabled: status %d", resp.StatusCode)
	}
}

func TestRuleListShowsThresholds(t *testing.T) {
	rules, _ := detection.LoadBuiltin()
	engine, _ := detection.NewEngine(rules)
	srv := New(config.Config{Port: "0"}, &mockClassifier{result: fixedResult}, WithDetections(engine))
	thresholds := 0
	for _, r := range getRules(t, srv) {
		if !r.Enabled {
			t.Fatalf("rules start enabled: %s", r.ID)
		}
		if r.Type == "threshold" {
			thresholds++
			if r.Threshold == "" {
				t.Fatalf("threshold rule without description: %+v", r)
			}
		}
	}
	if thresholds < 4 {
		t.Fatalf("want the built-in threshold rules, got %d", thresholds)
	}
}
