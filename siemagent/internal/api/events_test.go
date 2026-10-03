package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/chverma/siemagent/internal/models"
)

func getEvents(t *testing.T, url string) (int, []models.ClassifiedEvent) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var evs []models.ClassifiedEvent
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&evs); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return resp.StatusCode, evs
}

func TestEventsEmptyIsArray(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if strings.TrimSpace(string(body)) != "[]" {
		t.Fatalf("empty store should return [], got %s", body)
	}
}

func TestEventsListsClassifiedAndStreamedEvents(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	post := func(path string) {
		resp, err := http.Post(ts.URL+path, "application/json",
			strings.NewReader(`{"log":"Failed password for root from 10.0.0.1"}`))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	post("/api/classify")
	// Streamed classifications used to be returned but never stored.
	post("/api/classify/stream")

	code, evs := getEvents(t, ts.URL+"/api/events")
	if code != http.StatusOK || len(evs) != 2 {
		t.Fatalf("want 2 stored events, got status %d, %d events", code, len(evs))
	}
	if evs[0].AttackType != fixedResult.AttackType {
		t.Fatalf("unexpected event: %+v", evs[0])
	}

	code, evs = getEvents(t, ts.URL+"/api/events?limit=1")
	if code != http.StatusOK || len(evs) != 1 {
		t.Fatalf("limit=1: status %d, %d events", code, len(evs))
	}
}

func TestEventsRejectsBadLimit(t *testing.T) {
	_, ts := newTestServer()
	defer ts.Close()

	for _, limit := range []string{"0", "-1", "abc", "501"} {
		if code, _ := getEvents(t, ts.URL+"/api/events?limit="+limit); code != http.StatusBadRequest {
			t.Errorf("limit=%s: want 400, got %d", limit, code)
		}
	}
}

func TestSanitizeEventDoesNotMutateInput(t *testing.T) {
	ev := models.ClassifiedEvent{IOCs: []string{"1.2.3.4\x1b[31m"}}
	_ = sanitizeEvent(ev)
	if ev.IOCs[0] != "1.2.3.4\x1b[31m" {
		t.Fatalf("sanitizeEvent mutated the stored event: %q", ev.IOCs[0])
	}
}
