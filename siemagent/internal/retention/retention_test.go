package retention

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type call struct {
	kind   Kind
	cutoff time.Time
}

type fakePurger struct {
	mu    sync.Mutex
	calls []call
	fail  Kind
}

func (f *fakePurger) Purge(_ context.Context, kind Kind, cutoff time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{kind, cutoff})
	if kind == f.fail {
		return 0, errors.New("boom")
	}
	return 3, nil
}

var now = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

func TestDefaultPolicyOnlyPurgesExpiredSessions(t *testing.T) {
	p := &fakePurger{}
	r := New(Policy{}, p, 0)
	r.now = func() time.Time { return now }
	if r.Policy().Enabled() {
		t.Error("zero policy must not be enabled")
	}
	if r.Interval() != time.Hour {
		t.Errorf("default interval %v", r.Interval())
	}
	run := r.Once(context.Background())
	if len(p.calls) != 1 || p.calls[0].kind != Sessions || !p.calls[0].cutoff.Equal(now) {
		t.Fatalf("calls %+v", p.calls)
	}
	if run.Deleted[Sessions] != 3 || run.Deleted[Events] != 0 {
		t.Errorf("run %+v", run)
	}
}

func TestCutoffsFollowThePolicy(t *testing.T) {
	p := &fakePurger{}
	day := 24 * time.Hour
	r := New(Policy{Events: 30 * day, Incidents: 365 * day, Audit: 90 * day}, p, time.Minute)
	r.now = func() time.Time { return now }
	r.Once(context.Background())
	want := map[Kind]time.Time{
		Sessions:  now,
		Events:    now.Add(-30 * day),
		Incidents: now.Add(-365 * day),
		Audit:     now.Add(-90 * day),
	}
	if len(p.calls) != len(want) {
		t.Fatalf("calls %+v", p.calls)
	}
	for _, c := range p.calls {
		if !c.cutoff.Equal(want[c.kind]) {
			t.Errorf("%s cutoff %v, want %v", c.kind, c.cutoff, want[c.kind])
		}
	}
}

func TestFailureDoesNotStopOtherKinds(t *testing.T) {
	p := &fakePurger{fail: Events}
	r := New(Policy{Events: time.Hour, Audit: time.Hour}, p, time.Minute)
	if r.Last() != nil {
		t.Fatal("no run yet")
	}
	run := r.Once(context.Background())
	if run.Errors[Events] != "boom" || run.Deleted[Audit] != 3 {
		t.Fatalf("run %+v", run)
	}
	if last := r.Last(); last == nil || last.Errors[Events] != "boom" {
		t.Fatalf("last %+v", last)
	}
}

func TestStartRunsImmediatelyAndStops(t *testing.T) {
	p := &fakePurger{}
	r := New(Policy{}, p, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Start(ctx); close(done) }()
	deadline := time.After(2 * time.Second)
	for r.Last() == nil {
		select {
		case <-deadline:
			t.Fatal("first pass did not run")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return after cancel")
	}
}
