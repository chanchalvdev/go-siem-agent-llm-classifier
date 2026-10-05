package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chverma/siemagent/internal/config"
	"github.com/chverma/siemagent/internal/retention"
)

type stubPurger struct{}

func (stubPurger) Purge(context.Context, retention.Kind, time.Time) (int64, error) { return 2, nil }

func TestRetentionStatus(t *testing.T) {
	t.Run("without postgres", func(t *testing.T) {
		srv := New(config.Config{Port: "0"}, &mockClassifier{result: p2Result()})
		ts := httptest.NewServer(srv.router)
		defer ts.Close()
		var got retentionStatus
		if code := newClient(t, ts).do(http.MethodGet, "/api/retention", "", &got); code != http.StatusOK || got.Active || got.LastRun != nil {
			t.Fatalf("%d %+v", code, got)
		}
	})

	t.Run("with a policy", func(t *testing.T) {
		day := 24 * time.Hour
		runner := retention.New(retention.Policy{Events: 30 * day, Audit: 365 * day}, stubPurger{}, time.Hour)
		runner.Once(context.Background())
		srv := New(config.Config{Port: "0"}, &mockClassifier{result: p2Result()}, WithRetention(runner))
		ts := httptest.NewServer(srv.router)
		defer ts.Close()
		var got retentionStatus
		code := newClient(t, ts).do(http.MethodGet, "/api/retention", "", &got)
		if code != http.StatusOK || !got.Active || got.EventsDays != 30 || got.IncidentsDays != 0 || got.AuditDays != 365 ||
			got.IntervalSeconds != 3600 || got.LastRun == nil || got.LastRun.Deleted[retention.Events] != 2 {
			t.Fatalf("%d %+v", code, got)
		}
	})
}

func TestRetentionIsAdminOnly(t *testing.T) {
	ts, _ := usersServer(t)
	for user, want := range map[string]int{"ada": http.StatusOK, "ana": http.StatusForbidden, "vic": http.StatusForbidden} {
		c := newClient(t, ts)
		c.login(user)
		if code := c.do(http.MethodGet, "/api/retention", "", nil); code != want {
			t.Errorf("%s: %d, want %d", user, code, want)
		}
	}
}
