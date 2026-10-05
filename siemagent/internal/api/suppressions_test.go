package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/chverma/siemagent/internal/auth"
	"github.com/chverma/siemagent/internal/config"
	"github.com/chverma/siemagent/internal/incident"
	"github.com/chverma/siemagent/internal/models"
	"github.com/chverma/siemagent/internal/suppression"
)

func newSuppressions(t *testing.T) *suppression.Service {
	t.Helper()
	svc, err := suppression.NewService(context.Background(), suppression.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestSuppressedEventsStayOutOfIncidents(t *testing.T) {
	ts, inc := incidentServer(t, WithSuppressions(newSuppressions(t)))

	classifyLine(t, ts, "sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2")
	var list []incident.Incident
	doJSON(t, http.MethodGet, ts.URL+"/api/incidents", "", &list)
	if len(list) != 1 {
		t.Fatalf("want one incident before suppressing, got %d", len(list))
	}

	var sup suppression.Suppression
	body := `{"entity":"ip:203.0.113.9","reason":"authorised pentest","duration":"24h","incident_id":"` + list[0].ID + `"}`
	if code := doJSON(t, http.MethodPost, ts.URL+"/api/suppressions", body, &sup); code != http.StatusCreated || sup.ID == "" {
		t.Fatalf("create: %d %+v", code, sup)
	}
	// The snooze is recorded on the incident it was created from.
	d, err := inc.Get(context.Background(), list[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	last := d.Activity[len(d.Activity)-1]
	if last.Kind != incident.ActivitySuppression || !strings.Contains(last.Body, "ip:203.0.113.9") || !strings.Contains(last.Body, "authorised pentest") {
		t.Fatalf("timeline note: %+v", last)
	}

	// The suppressed IP is stored and marked, but opens no incident.
	b, _ := json.Marshal(models.ClassifyRequest{Log: "sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2"})
	resp, err := http.Post(ts.URL+"/api/classify", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	var ev models.ClassifiedEvent
	_ = json.NewDecoder(resp.Body).Decode(&ev)
	_ = resp.Body.Close()
	if ev.SuppressedBy != sup.ID {
		t.Fatalf("classify response not marked suppressed: %q", ev.SuppressedBy)
	}
	var events []models.ClassifiedEvent
	doJSON(t, http.MethodGet, ts.URL+"/api/events?limit=10", "", &events)
	if len(events) != 2 || events[0].SuppressedBy != sup.ID {
		t.Fatalf("stored events: %+v", events)
	}
	doJSON(t, http.MethodGet, ts.URL+"/api/incidents", "", &list)
	if len(list) != 1 || list[0].AlertCount != 1 {
		t.Fatalf("suppressed event reached incidents: %+v", list)
	}

	var all []suppression.Suppression
	doJSON(t, http.MethodGet, ts.URL+"/api/suppressions", "", &all)
	if len(all) != 1 || all[0].Hits != 1 {
		t.Fatalf("list: %+v", all)
	}

	// Lifting it makes the IP alert again: it joins the open incident
	// through the shared user:root.
	if code := doJSON(t, http.MethodDelete, ts.URL+"/api/suppressions/"+sup.ID, "", nil); code != http.StatusNoContent {
		t.Fatalf("lift: %d", code)
	}
	classifyLine(t, ts, "sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2")
	doJSON(t, http.MethodGet, ts.URL+"/api/incidents", "", &list)
	if len(list) != 1 || list[0].AlertCount != 2 {
		t.Fatalf("after lift the alert must reach the incident: %+v", list)
	}
	if code := doJSON(t, http.MethodDelete, ts.URL+"/api/suppressions/"+sup.ID, "", nil); code != http.StatusNotFound {
		t.Fatalf("lift twice: %d", code)
	}
}

func TestSuppressionValidationAndRoles(t *testing.T) {
	ts, _ := incidentServer(t, WithSuppressions(newSuppressions(t)))
	var e map[string]string
	if code := doJSON(t, http.MethodPost, ts.URL+"/api/suppressions", `{"reason":"x"}`, &e); code != http.StatusBadRequest || !strings.Contains(e["error"], "at least one") {
		t.Fatalf("no matcher: %d %v", code, e)
	}
}

func TestSuppressionRoles(t *testing.T) {
	ctx := context.Background()
	users, err := auth.NewService(ctx, auth.NewMemory(), 0)
	if err != nil {
		t.Fatal(err)
	}
	users.SetHashCost(bcrypt.MinCost)
	for name, role := range map[string]auth.Role{"ana": auth.RoleAnalyst, "vic": auth.RoleViewer} {
		if _, err := users.CreateUser(ctx, "test", auth.NewUser{Username: name, Password: testPW, Role: role}); err != nil {
			t.Fatal(err)
		}
	}
	srv := New(config.Config{Port: "0"}, &mockClassifier{result: p2Result()}, WithUsers(users), WithSuppressions(newSuppressions(t)))
	ts := httptest.NewServer(srv.router)
	defer ts.Close()

	vic := newClient(t, ts)
	vic.login("vic")
	if code := vic.do(http.MethodGet, "/api/suppressions", "", nil); code != http.StatusOK {
		t.Fatalf("viewer list: %d", code)
	}
	if code := vic.do(http.MethodPost, "/api/suppressions", `{"rule_id":"r","reason":"x"}`, nil); code != http.StatusForbidden {
		t.Fatalf("viewer create: %d", code)
	}
	ana := newClient(t, ts)
	ana.login("ana")
	var sup suppression.Suppression
	if code := ana.do(http.MethodPost, "/api/suppressions", `{"rule_id":"r","reason":"x"}`, &sup); code != http.StatusCreated || sup.CreatedBy != "ana" {
		t.Fatalf("analyst create: %d %+v", code, sup)
	}
	if code := vic.do(http.MethodDelete, "/api/suppressions/"+sup.ID, "", nil); code != http.StatusForbidden {
		t.Fatalf("viewer lift: %d", code)
	}
}

func TestSuppressionsDisabled(t *testing.T) {
	ts, _ := incidentServer(t)
	if code := doJSON(t, http.MethodGet, ts.URL+"/api/suppressions", "", nil); code != http.StatusNotFound {
		t.Fatalf("got %d", code)
	}
}
