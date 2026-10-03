package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	openai "github.com/sashabaranov/go-openai"

	"github.com/chverma/siemagent/internal/agent"
	"github.com/chverma/siemagent/internal/config"
	"github.com/chverma/siemagent/internal/incident"
	"github.com/chverma/siemagent/internal/models"
)

func p2Result() models.ClassifiedEvent {
	r := fixedResult
	r.Severity = models.SeverityP2
	r.AttackType = "Brute Force"
	r.MITRE = models.MITREInfo{Tactic: "Credential Access", TechniqueID: "T1110"}
	return r
}

func incidentServer(t *testing.T, opts ...ServerOption) (*httptest.Server, *incident.Service) {
	t.Helper()
	svc := incident.NewService(incident.NewMemory(), incident.DefaultConfig())
	srv := New(config.Config{Port: "0"}, &mockClassifier{result: p2Result()}, append(opts, WithIncidents(svc))...)
	ts := httptest.NewServer(srv.router)
	t.Cleanup(ts.Close)
	return ts, svc
}

func doJSON(t *testing.T, method, url, body string, out any) int {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func classifyLine(t *testing.T, ts *httptest.Server, line string) {
	t.Helper()
	b, _ := json.Marshal(models.ClassifyRequest{Log: line})
	resp, err := http.Post(ts.URL+"/api/classify", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("classify: %d", resp.StatusCode)
	}
}

func TestIncidentLifecycleOverHTTP(t *testing.T) {
	ts, _ := incidentServer(t)
	for _, port := range []string{"1", "2"} {
		classifyLine(t, ts, "sshd[1]: Failed password for root from 203.0.113.7 port "+port+" ssh2")
	}
	classifyLine(t, ts, "sshd[1]: Failed password for admin from 198.51.100.1 port 22 ssh2")

	var list []incident.Incident
	if code := doJSON(t, http.MethodGet, ts.URL+"/api/incidents", "", &list); code != http.StatusOK {
		t.Fatalf("list: %d", code)
	}
	if len(list) != 2 {
		t.Fatalf("two source IPs should give two incidents, got %d", len(list))
	}
	var byIP []incident.Incident
	doJSON(t, http.MethodGet, ts.URL+"/api/incidents?entity=ip:203.0.113.7", "", &byIP)
	if len(byIP) != 1 || byIP[0].AlertCount != 2 {
		t.Fatalf("entity filter: %+v", byIP)
	}
	id := byIP[0].ID

	var updated incident.Incident
	code := doJSON(t, http.MethodPatch, ts.URL+"/api/incidents/"+id,
		`{"status":"resolved","resolution":"true_positive","assignee":"alice"}`, &updated)
	if code != http.StatusOK || updated.Status != incident.StatusResolved || updated.Assignee != "alice" {
		t.Fatalf("update: %d %+v", code, updated)
	}
	var act incident.Activity
	if code := doJSON(t, http.MethodPost, ts.URL+"/api/incidents/"+id+"/comments", `{"body":"Blocked at the edge."}`, &act); code != http.StatusCreated || act.Actor != "analyst" {
		t.Fatalf("comment: %d %+v", code, act)
	}

	var d incident.Detail
	doJSON(t, http.MethodGet, ts.URL+"/api/incidents/"+id, "", &d)
	if len(d.Alerts) != 2 || d.Activity[len(d.Activity)-1].Body != "Blocked at the edge." {
		t.Fatalf("detail: %+v", d)
	}

	var stats incident.Stats
	doJSON(t, http.MethodGet, ts.URL+"/api/incidents/stats", "", &stats)
	if stats.Open != 1 || stats.Resolved != 1 {
		t.Fatalf("stats: %+v", stats)
	}
}

func TestIncidentAPIErrors(t *testing.T) {
	ts, _ := incidentServer(t)
	classifyLine(t, ts, "sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2")
	var list []incident.Incident
	doJSON(t, http.MethodGet, ts.URL+"/api/incidents", "", &list)
	id := list[0].ID

	var e map[string]string
	cases := []struct {
		method, path, body string
		want               int
		msg                string
	}{
		{http.MethodGet, "/api/incidents/INC-NOPE", "", http.StatusNotFound, "incident not found"},
		{http.MethodPatch, "/api/incidents/" + id, `{"status":"closed"}`, http.StatusBadRequest, "status must be"},
		{http.MethodPatch, "/api/incidents/" + id, `not json`, http.StatusBadRequest, "invalid JSON"},
		{http.MethodPost, "/api/incidents/" + id + "/comments", `{"body":"  "}`, http.StatusBadRequest, "comment is empty"},
		{http.MethodGet, "/api/incidents?entity=mac:aa", "", http.StatusBadRequest, "entity kind"},
		{http.MethodGet, "/api/incidents?limit=0", "", http.StatusBadRequest, "limit"},
	}
	for _, c := range cases {
		e = nil
		if code := doJSON(t, c.method, ts.URL+c.path, c.body, &e); code != c.want || !strings.Contains(e["error"], c.msg) {
			t.Errorf("%s %s: %d %v, want %d %q", c.method, c.path, code, e, c.want, c.msg)
		}
	}
}

func TestIncidentRoutesWithoutService(t *testing.T) {
	srv := New(config.Config{Port: "0"}, &mockClassifier{result: fixedResult})
	ts := httptest.NewServer(srv.router)
	defer ts.Close()
	if code := doJSON(t, http.MethodGet, ts.URL+"/api/incidents", "", nil); code != http.StatusNotFound {
		t.Fatalf("want 404 without incidents, got %d", code)
	}
}

func TestIncidentDetailIsSanitized(t *testing.T) {
	ts, svc := incidentServer(t)
	classifyLine(t, ts, "sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2 \x1b[31mred")
	list, _ := svc.List(context.Background(), incident.Filter{})
	var d incident.Detail
	doJSON(t, http.MethodGet, ts.URL+"/api/incidents/"+list[0].ID, "", &d)
	if strings.Contains(d.Alerts[0].Raw, "\x1b") {
		t.Fatalf("raw alert text not sanitized: %q", d.Alerts[0].Raw)
	}
}

// countingLLM answers the agent's calls without tools and counts streamed
// write-ups, which happen once per investigation.
func countingLLM(t *testing.T) (*openai.Client, *atomic.Int64) {
	t.Helper()
	var streams atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"stream":true`) {
			streams.Add(1)
			w.Header().Set("Content-Type", "text/event-stream")
			chunk := openai.ChatCompletionStreamResponse{Choices: []openai.ChatCompletionStreamChoice{{
				Delta: openai.ChatCompletionStreamChoiceDelta{Content: "## Summary\nBlock the source."},
			}}}
			b, _ := json.Marshal(chunk)
			_, _ = w.Write([]byte("data: " + string(b) + "\n\ndata: [DONE]\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(openai.ChatCompletionResponse{Choices: []openai.ChatCompletionChoice{{
			Message: openai.ChatCompletionMessage{Role: "assistant", Content: "ok"}, FinishReason: "stop",
		}}})
	}))
	t.Cleanup(srv.Close)
	cfg := openai.DefaultConfig("test")
	cfg.BaseURL = srv.URL
	return openai.NewClientWithConfig(cfg), &streams
}

func TestOneInvestigationPerIncidentSavedToHistory(t *testing.T) {
	client, streams := countingLLM(t)
	ts, svc := incidentServer(t, WithAgent(NewHub(), client, "model", agent.New()))
	for _, port := range []string{"1", "2", "3", "4"} {
		classifyLine(t, ts, "sshd[1]: Failed password for root from 203.0.113.7 port "+port+" ssh2")
	}

	list, _ := svc.List(context.Background(), incident.Filter{})
	if len(list) != 1 {
		t.Fatalf("want one incident, got %d", len(list))
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		d, _ := svc.Get(context.Background(), list[0].ID)
		var notes []incident.Activity
		for _, a := range d.Activity {
			if a.Kind == incident.ActivityInvestigation {
				notes = append(notes, a)
			}
		}
		if len(notes) == 1 {
			if notes[0].Actor != "ai-agent" || !strings.Contains(notes[0].Body, "Block the source") {
				t.Fatalf("note = %+v", notes[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("investigation not saved; activity = %+v", d.Activity)
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // let any extra (wrong) runs show up
	if n := streams.Load(); n != 1 {
		t.Fatalf("four alerts in one incident should run one investigation, ran %d", n)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func countKind(t *testing.T, svc *incident.Service, id, kind string) int {
	t.Helper()
	d, _ := svc.Get(context.Background(), id)
	n := 0
	for _, a := range d.Activity {
		if a.Kind == kind {
			n++
		}
	}
	return n
}

func TestOnDemandInvestigationReportAndFeedback(t *testing.T) {
	client, streams := countingLLM(t)
	svc := incident.NewService(incident.NewMemory(), incident.DefaultConfig())
	r := fixedResult
	r.Severity = models.SeverityP3 // below auto-investigation
	srv := New(config.Config{Port: "0"}, &mockClassifier{result: r},
		WithIncidents(svc), WithAgent(NewHub(), client, "model", agent.New()))
	ts := httptest.NewServer(srv.router)
	defer ts.Close()

	classifyLine(t, ts, "sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2")
	list, _ := svc.List(context.Background(), incident.Filter{})
	id := list[0].ID

	var e map[string]string
	if code := doJSON(t, http.MethodPost, ts.URL+"/api/incidents/"+id+"/feedback", `{"helpful":true}`, &e); code != http.StatusBadRequest {
		t.Fatalf("feedback before any investigation: %d %v", code, e)
	}
	if streams.Load() != 0 {
		t.Fatal("P3 must not auto-investigate")
	}

	if code := doJSON(t, http.MethodPost, ts.URL+"/api/incidents/"+id+"/investigate", "", nil); code != http.StatusAccepted {
		t.Fatalf("investigate: %d", code)
	}
	waitFor(t, "investigation note", func() bool { return countKind(t, svc, id, incident.ActivityInvestigation) == 1 })

	resp, err := http.Get(ts.URL + "/api/incidents/" + id + "/report?download=1")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/markdown") ||
		resp.Header.Get("Content-Disposition") != `attachment; filename="`+id+`-report.md"` {
		t.Fatalf("headers: %v", resp.Header)
	}
	if !strings.Contains(string(body), "## AI investigation") || !strings.Contains(string(body), "Block the source.") {
		t.Fatalf("report:\n%s", body)
	}

	var act incident.Activity
	if code := doJSON(t, http.MethodPost, ts.URL+"/api/incidents/"+id+"/feedback", `{"helpful":false,"note":"too vague"}`, &act); code != http.StatusCreated || act.Kind != incident.ActivityFeedback {
		t.Fatalf("feedback: %d %+v", code, act)
	}
	if code := doJSON(t, http.MethodPost, ts.URL+"/api/incidents/"+id+"/feedback", `{"note":"x"}`, nil); code != http.StatusBadRequest {
		t.Fatalf("feedback without rating: %d", code)
	}
}

func TestInvestigateErrors(t *testing.T) {
	// No agent configured.
	ts, svc := incidentServer(t)
	classifyLine(t, ts, "sshd[1]: Failed password for root from 203.0.113.7 port 1 ssh2")
	list, _ := svc.List(context.Background(), incident.Filter{})
	if code := doJSON(t, http.MethodPost, ts.URL+"/api/incidents/"+list[0].ID+"/investigate", "", nil); code != http.StatusServiceUnavailable {
		t.Fatalf("no agent: %d", code)
	}
	if code := doJSON(t, http.MethodPost, ts.URL+"/api/incidents/INC-NOPE/investigate", "", nil); code != http.StatusNotFound {
		t.Fatalf("unknown incident: %d", code)
	}
	if code := doJSON(t, http.MethodGet, ts.URL+"/api/incidents/INC-NOPE/report", "", nil); code != http.StatusNotFound {
		t.Fatalf("unknown report: %d", code)
	}
}

func TestInvestigationRunsOncePerIncidentAtATime(t *testing.T) {
	client := openai.NewClientWithConfig(openai.DefaultConfig("unused"))
	svc := incident.NewService(incident.NewMemory(), incident.DefaultConfig())
	srv := New(config.Config{Port: "0"}, &mockClassifier{result: fixedResult},
		WithIncidents(svc), WithAgent(NewHub(), client, "model", agent.New()))

	srv.agent.running["INC-BUSY"] = true
	if err := srv.investigateIncident("INC-BUSY", ""); err != errAlreadyRunning {
		t.Fatalf("want errAlreadyRunning, got %v", err)
	}
	for range maxConcurrentInvestigations {
		srv.agent.slots <- struct{}{}
	}
	if err := srv.investigateIncident("INC-OTHER", ""); err != errAgentBusy {
		t.Fatalf("want errAgentBusy, got %v", err)
	}
	if srv.agent.running["INC-OTHER"] {
		t.Fatal("a refused run must not be marked running")
	}
}
