package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chverma/siemagent/internal/config"
	"github.com/chverma/siemagent/internal/incident"
	"github.com/chverma/siemagent/internal/response"
)

// responseServer wires incidents and the built-in playbooks to a fake
// containment webhook that counts calls.
func responseServer(t *testing.T) (*httptest.Server, *incident.Service, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		calls.Add(1)
		_, _ = w.Write([]byte("blocked"))
	}))
	t.Cleanup(hook.Close)

	svc := incident.NewService(incident.NewMemory(), incident.DefaultConfig())
	pbs, _ := response.LoadBuiltin()
	eng, _ := response.NewEngine(pbs, response.NewMemory(),
		response.NewHTTPExecutor(response.Connectors{ContainmentURL: hook.URL}), svc)
	r := p2Result()
	r.MITRE.TechniqueID = "T1110.001"
	srv := New(config.Config{Port: "0"}, &mockClassifier{result: r}, WithIncidents(svc), WithResponse(eng))
	ts := httptest.NewServer(srv.router)
	t.Cleanup(ts.Close)
	return ts, svc, &calls
}

func TestResponseApprovalFlowOverHTTP(t *testing.T) {
	ts, svc, calls := responseServer(t)
	classifyLine(t, ts, "sshd[1]: Failed password for root from 185.220.101.4 port 22 ssh2")

	var pending []response.Action
	doJSON(t, http.MethodGet, ts.URL+"/api/response/actions?status=pending", "", &pending)
	if len(pending) != 1 || pending[0].Type != response.ActionBlockIP || pending[0].Target != "185.220.101.4" {
		t.Fatalf("pending = %+v", pending)
	}
	if calls.Load() != 0 {
		t.Fatal("nothing may run before approval")
	}

	var done response.Action
	if code := doJSON(t, http.MethodPost, ts.URL+"/api/response/actions/"+pending[0].ID+"/approve", "", &done); code != http.StatusOK {
		t.Fatalf("approve: %d", code)
	}
	if done.Status != response.StatusSucceeded || done.DecidedBy != "analyst" || calls.Load() != 1 {
		t.Fatalf("approved = %+v, calls = %d", done, calls.Load())
	}
	var e map[string]string
	if code := doJSON(t, http.MethodPost, ts.URL+"/api/response/actions/"+pending[0].ID+"/approve", "", &e); code != http.StatusConflict {
		t.Fatalf("re-approve: %d %v", code, e)
	}

	d, _ := svc.Get(context.Background(), pending[0].IncidentID)
	var trail []string
	for _, a := range d.Activity {
		if a.Kind == incident.ActivityResponse {
			trail = append(trail, a.Body)
		}
	}
	if len(trail) != 3 || !strings.HasPrefix(trail[2], "Executed block_ip 185.220.101.4") {
		t.Fatalf("audit trail = %v", trail)
	}
}

func TestRejectAndManualRunOverHTTP(t *testing.T) {
	ts, svc, calls := responseServer(t)
	classifyLine(t, ts, "<34>1 2026-10-03T10:00:00Z web01 sshd 1 - Failed password for root from 185.220.101.4 port 22 ssh2")
	var pending []response.Action
	doJSON(t, http.MethodGet, ts.URL+"/api/response/actions", "", &pending)

	var rejected response.Action
	if code := doJSON(t, http.MethodPost, ts.URL+"/api/response/actions/"+pending[0].ID+"/reject", `{"reason":"authorised scan"}`, &rejected); code != http.StatusOK || rejected.Status != response.StatusRejected {
		t.Fatalf("reject: %d %+v", code, rejected)
	}
	if calls.Load() != 0 {
		t.Fatal("rejected action ran")
	}

	list, _ := svc.List(context.Background(), incident.Filter{})
	var acts []response.Action
	code := doJSON(t, http.MethodPost, ts.URL+"/api/incidents/"+list[0].ID+"/playbooks/ransomware-isolation/run", "", &acts)
	if code != http.StatusOK || len(acts) != 2 || acts[0].Type != response.ActionIsolateHost || acts[0].Target != "web01" {
		t.Fatalf("manual run: %d %+v", code, acts)
	}
	var byIncident []response.Action
	doJSON(t, http.MethodGet, ts.URL+"/api/response/actions?incident="+list[0].ID, "", &byIncident)
	if len(byIncident) != 3 {
		t.Fatalf("incident filter: %d", len(byIncident))
	}

	for path, want := range map[string]int{
		"/api/incidents/" + list[0].ID + "/playbooks/nope/run":       http.StatusConflict,
		"/api/incidents/INC-NOPE/playbooks/ransomware-isolation/run": http.StatusNotFound,
		"/api/response/actions/ACT-NOPE/approve":                     http.StatusNotFound,
	} {
		if code := doJSON(t, http.MethodPost, ts.URL+path, "", nil); code != want {
			t.Errorf("%s: %d, want %d", path, code, want)
		}
	}
	if code := doJSON(t, http.MethodGet, ts.URL+"/api/response/actions?limit=0", "", nil); code != http.StatusBadRequest {
		t.Errorf("bad limit: %d", code)
	}
}

func TestPlaybooksEndpoint(t *testing.T) {
	ts, _, _ := responseServer(t)
	var pbs []struct {
		ID      string `json:"id"`
		Mode    string `json:"mode"`
		Enabled bool   `json:"enabled"`
		Actions []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"actions"`
	}
	doJSON(t, http.MethodGet, ts.URL+"/api/playbooks", "", &pbs)
	if len(pbs) < 4 || !pbs[0].Enabled || pbs[0].Mode == "" {
		t.Fatalf("playbooks = %+v", pbs)
	}

	srv := New(config.Config{Port: "0"}, &mockClassifier{result: fixedResult})
	plain := httptest.NewServer(srv.router)
	defer plain.Close()
	if code := doJSON(t, http.MethodGet, plain.URL+"/api/playbooks", "", nil); code != http.StatusNotFound {
		t.Fatalf("without engine: %d", code)
	}
}
