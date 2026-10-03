package pipeline

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/chverma/siemagent/internal/models"
)

type fakeClassifier struct {
	block chan struct{} // when non-nil, Classify waits on it
}

func (f *fakeClassifier) Classify(_ context.Context, ev models.LogEvent) (models.ClassifiedEvent, error) {
	if f.block != nil {
		<-f.block
	}
	if ev.Message == "fail" {
		return models.ClassifiedEvent{}, errors.New("boom")
	}
	return models.ClassifiedEvent{Event: ev, AttackType: "x"}, nil
}

func (f *fakeClassifier) ClassifyStream(ctx context.Context, ev models.LogEvent, _ func(string)) (models.ClassifiedEvent, error) {
	return f.Classify(ctx, ev)
}

func (f *fakeClassifier) Ping(context.Context) error { return nil }

func TestPoolClassifiesAndSkipsErrors(t *testing.T) {
	p := NewWorkerPool(3, &fakeClassifier{})
	out := p.Start(context.Background())
	for _, m := range []string{"a", "fail", "b", "c"} {
		p.Submit(models.LogEvent{Message: m})
	}
	p.Close()

	got := 0
	for range out {
		got++
	}
	if got != 3 {
		t.Fatalf("want 3 classified events, got %d", got)
	}
}

func TestTrySubmitShedsLoadWhenFull(t *testing.T) {
	block := make(chan struct{})
	p := NewWorkerPoolWithQueue(1, 2, &fakeClassifier{block: block})
	out := p.Start(context.Background())

	// One event is taken by the blocked worker, two fill the queue.
	accepted := 0
	for range 10 {
		if p.TrySubmit(models.LogEvent{Message: "m"}) {
			accepted++
		}
	}
	if accepted < 2 || accepted > 3 {
		t.Fatalf("expected 2-3 accepted events before shedding, got %d", accepted)
	}

	close(block)
	p.Close()
	got := 0
	for range out {
		got++
	}
	if got != accepted {
		t.Fatalf("every accepted event should be classified: accepted %d, got %d", accepted, got)
	}
}

func TestTrySubmitAfterCloseIsSafe(t *testing.T) {
	p := NewWorkerPool(2, &fakeClassifier{})
	out := p.Start(context.Background())

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				p.TrySubmit(models.LogEvent{Message: "m"})
			}
		}()
	}
	p.Close()
	p.Close() // idempotent
	wg.Wait()
	for range out {
	}
	if p.TrySubmit(models.LogEvent{}) {
		t.Fatal("TrySubmit must refuse after Close")
	}
}
