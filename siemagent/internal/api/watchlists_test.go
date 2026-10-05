package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/chverma/siemagent/internal/auth"
	"github.com/chverma/siemagent/internal/config"
	"github.com/chverma/siemagent/internal/incident"
	"github.com/chverma/siemagent/internal/ioc"
	"github.com/chverma/siemagent/internal/models"
)

// watchlistServer has accounts for every role and an LLM that calls
// everything benign, so any alert must come from a watchlist.
func watchlistServer(t *testing.T) (*httptest.Server, *incident.Service) {
	t.Helper()
	ctx := context.Background()
	users, err := auth.NewService(ctx, auth.NewMemory(), 0)
	if err != nil {
		t.Fatal(err)
	}
	users.SetHashCost(bcrypt.MinCost)
	for name, role := range map[string]auth.Role{"ada": auth.RoleAdmin, "ana": auth.RoleAnalyst, "vic": auth.RoleViewer} {
		if _, err := users.CreateUser(ctx, "test", auth.NewUser{Username: name, Password: testPW, Role: role}); err != nil {
			t.Fatal(err)
		}
	}
	wl, err := ioc.NewService(ctx, ioc.NewMemory())
	if err != nil {
		t.Fatal(err)
	}
	benign := models.ClassifiedEvent{AttackType: "Normal Activity", Severity: models.SeverityP5, IOCs: []string{}, Summary: "Routine."}
	inc := incident.NewService(incident.NewMemory(), incident.DefaultConfig())
	srv := New(config.Config{Port: "0"}, &mockClassifier{result: benign},
		WithUsers(users), WithIncidents(inc), WithWatchlists(wl))
	ts := httptest.NewServer(srv.router)
	t.Cleanup(ts.Close)
	return ts, inc
}

func login(t *testing.T, ts *httptest.Server, user string) *client {
	t.Helper()
	c := newClient(t, ts)
	c.login(user)
	return c
}

func TestWatchlistMatchOpensIncident(t *testing.T) {
	ts, inc := watchlistServer(t)
	ada, ana := login(t, ts, "ada"), login(t, ts, "ana")

	var wl ioc.Watchlist
	if code := ada.do(http.MethodPost, "/api/watchlists", `{"name":"Case 42 C2","source":"manual","severity":"P1"}`, &wl); code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	var added addIndicatorsResponse
	code := ana.do(http.MethodPost, "/api/watchlists/"+wl.ID+"/indicators",
		`{"values":["203.0.113.9","198.51.100.0/24","not valid!"],"note":"from the phishing case"}`, &added)
	if code != http.StatusOK || len(added.Added) != 2 || len(added.Rejected) != 1 {
		t.Fatalf("add: %d %+v", code, added)
	}

	var ev models.ClassifiedEvent
	if code := ana.do(http.MethodPost, "/api/classify", `{"log":"Accepted password for svc from 198.51.100.44 port 22 ssh2"}`, &ev); code != http.StatusOK {
		t.Fatalf("classify: %d", code)
	}
	if ev.Severity != models.SeverityP1 || ev.AttackType != "Known Malicious Indicator" ||
		len(ev.Detections) != 1 || ev.Detections[0].RuleID != "ioc:"+wl.ID {
		t.Fatalf("watchlist did not raise the event: %+v", ev)
	}
	list, _ := inc.List(context.Background(), incident.Filter{Limit: 10})
	if len(list) != 1 || list[0].Severity != models.SeverityP1 {
		t.Fatalf("a P1 watchlist hit must open an incident: %+v", list)
	}

	var lists []ioc.Watchlist
	ana.do(http.MethodGet, "/api/watchlists", "", &lists)
	if len(lists) != 1 || lists[0].Hits != 1 || lists[0].Count != 2 {
		t.Fatalf("list: %+v", lists)
	}
	var page indicatorPage
	ana.do(http.MethodGet, "/api/watchlists/"+wl.ID+"/indicators?limit=1", "", &page)
	if page.Total != 2 || len(page.Indicators) != 1 || page.Indicators[0].Note != "from the phishing case" || page.Indicators[0].AddedBy != "ana" {
		t.Fatalf("indicators: %+v", page)
	}
	var found []ioc.LookupResult
	ana.do(http.MethodGet, "/api/ioc/lookup?value="+url.QueryEscape("198.51.100.200"), "", &found)
	if len(found) != 1 || found[0].Indicator != "198.51.100.0/24" {
		t.Fatalf("lookup: %+v", found)
	}

	// Ranges contain "/", so the value travels in the query string.
	if code := ana.do(http.MethodDelete, "/api/watchlists/"+wl.ID+"/indicators?value="+url.QueryEscape("198.51.100.0/24"), "", nil); code != http.StatusNoContent {
		t.Fatalf("remove: %d", code)
	}
	ana.do(http.MethodGet, "/api/ioc/lookup?value=198.51.100.200", "", &found)
	if len(found) != 0 {
		t.Fatalf("removed range still listed: %+v", found)
	}
}

func TestWatchlistRoles(t *testing.T) {
	ts, _ := watchlistServer(t)
	ada, ana, vic := login(t, ts, "ada"), login(t, ts, "ana"), login(t, ts, "vic")
	var wl ioc.Watchlist
	ada.do(http.MethodPost, "/api/watchlists", `{"name":"Known bad","source":"manual"}`, &wl)

	for _, tc := range []struct {
		c      *client
		method string
		path   string
		body   string
		want   int
	}{
		{vic, http.MethodGet, "/api/watchlists", "", http.StatusOK},
		{vic, http.MethodGet, "/api/ioc/lookup?value=1.2.3.4", "", http.StatusOK},
		{vic, http.MethodPost, "/api/watchlists/" + wl.ID + "/indicators", `{"values":["1.2.3.4"]}`, http.StatusForbidden},
		{ana, http.MethodPost, "/api/watchlists", `{"name":"x","source":"manual"}`, http.StatusForbidden},
		{ana, http.MethodPatch, "/api/watchlists/" + wl.ID, `{"enabled":false}`, http.StatusForbidden},
		{ana, http.MethodDelete, "/api/watchlists/" + wl.ID, "", http.StatusForbidden},
		{ada, http.MethodPatch, "/api/watchlists/" + wl.ID, `{"severity":"P1","enabled":false}`, http.StatusOK},
		{ada, http.MethodPost, "/api/watchlists", `{"name":"x","source":"feed","url":"ftp://x"}`, http.StatusBadRequest},
		{ada, http.MethodPost, "/api/watchlists/" + wl.ID + "/refresh", "", http.StatusConflict},
		{ada, http.MethodDelete, "/api/watchlists/WL-NOPE", "", http.StatusNotFound},
		{ada, http.MethodDelete, "/api/watchlists/" + wl.ID, "", http.StatusNoContent},
	} {
		if code := tc.c.do(tc.method, tc.path, tc.body, nil); code != tc.want {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.path, code, tc.want)
		}
	}
}

func TestWatchlistFeedRefresh(t *testing.T) {
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "# test feed\n203.0.113.66\nevil.example")
	}))
	defer feed.Close()
	ts, _ := watchlistServer(t)
	ada := login(t, ts, "ada")

	var wl ioc.Watchlist
	body := fmt.Sprintf(`{"name":"Test feed","source":"feed","url":%q,"severity":"P3"}`, feed.URL)
	if code := ada.do(http.MethodPost, "/api/watchlists", body, &wl); code != http.StatusCreated || wl.RefreshSeconds != 21600 {
		t.Fatalf("create feed: %d %+v", code, wl)
	}
	if code := ada.do(http.MethodPost, "/api/watchlists/"+wl.ID+"/refresh", "", &wl); code != http.StatusOK || wl.Count != 2 || wl.Error != "" {
		t.Fatalf("refresh: %d %+v", code, wl)
	}
	var ev models.ClassifiedEvent
	ada.do(http.MethodPost, "/api/classify", `{"log":"dns query beacon.evil.example"}`, &ev)
	if ev.Severity != models.SeverityP3 {
		t.Fatalf("feed indicator not matched: %+v", ev)
	}
	if code := ada.do(http.MethodPost, "/api/watchlists/"+wl.ID+"/indicators", `{"values":["1.2.3.4"]}`, nil); code != http.StatusConflict {
		t.Fatalf("feeds are read-only: %d", code)
	}
}
