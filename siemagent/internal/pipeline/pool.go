package pipeline

import (
	"context"
	"log/slog"
	"sync"

	"github.com/chverma/siemagent/internal/classifier"
	"github.com/chverma/siemagent/internal/models"
)

// WorkerPool fans out LogEvents to N classifier goroutines and collects results.
type WorkerPool struct {
	n          int
	classifier classifier.Interface
	in         chan models.LogEvent
	out        chan models.ClassifiedEvent
	wg         sync.WaitGroup

	mu     sync.RWMutex // guards closed against concurrent TrySubmit/Close
	closed bool
}

func NewWorkerPool(n int, c classifier.Interface) *WorkerPool {
	return NewWorkerPoolWithQueue(n, n*4, c)
}

// NewWorkerPoolWithQueue sets the input queue depth explicitly. Long-running
// streams use a deeper queue so short bursts are absorbed instead of dropped.
func NewWorkerPoolWithQueue(n, queue int, c classifier.Interface) *WorkerPool {
	return &WorkerPool{
		n:          n,
		classifier: c,
		in:         make(chan models.LogEvent, queue),
		out:        make(chan models.ClassifiedEvent, n*4),
	}
}

// Start launches worker goroutines and returns the results channel.
// Call Close() after all events are submitted to signal end of input.
func (p *WorkerPool) Start(ctx context.Context) <-chan models.ClassifiedEvent {
	for i := range p.n {
		p.wg.Add(1)
		go func(id int) {
			defer p.wg.Done()
			for ev := range p.in {
				classified, err := p.classifier.Classify(ctx, ev)
				if err != nil {
					slog.Warn("classify failed", "component", "pipeline", "worker", id, "error", err)
					continue
				}
				p.out <- classified
			}
		}(i)
	}

	go func() {
		p.wg.Wait()
		close(p.out)
	}()

	return p.out
}

// Submit sends an event to the pool, blocking while the queue is full.
// Must be called after Start.
func (p *WorkerPool) Submit(ev models.LogEvent) {
	p.in <- ev
}

// TrySubmit queues an event without blocking. It returns false when the
// queue is full or the pool is closed, so a network listener can shed load
// instead of stalling its senders.
func (p *WorkerPool) TrySubmit(ev models.LogEvent) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return false
	}
	select {
	case p.in <- ev:
		return true
	default:
		return false
	}
}

// Close signals no more events and lets workers drain. Safe to call twice.
func (p *WorkerPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		close(p.in)
	}
}
