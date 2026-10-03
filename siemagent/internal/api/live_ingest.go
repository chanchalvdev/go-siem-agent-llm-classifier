package api

import (
	"context"
	"sync"

	"github.com/chverma/siemagent/internal/metrics"
	"github.com/chverma/siemagent/internal/models"
	"github.com/chverma/siemagent/internal/pipeline"
)

// liveQueueDepth absorbs bursts from network senders; beyond it lines are
// dropped (and counted) rather than blocking the listener.
const liveQueueDepth = 1000

// LiveIngest classifies a continuous stream of log lines (e.g. from the
// syslog listener) and records each result like any API classification.
type LiveIngest struct {
	srv  *Server
	pool *pipeline.WorkerPool
	done sync.WaitGroup
}

// StartLiveIngest starts the classification workers. Call Close when the
// producers have stopped.
func (s *Server) StartLiveIngest(ctx context.Context) *LiveIngest {
	li := &LiveIngest{
		srv:  s,
		pool: pipeline.NewWorkerPoolWithQueue(s.cfg.Workers, liveQueueDepth, s.classifier),
	}
	out := li.pool.Start(ctx)
	li.done.Add(1)
	go func() {
		defer li.done.Done()
		for ev := range out {
			s.record(ev)
		}
	}()
	return li
}

// Submit parses one raw line and queues it for classification. It never
// blocks; it returns false when the line was dropped.
func (li *LiveIngest) Submit(transport, line string) bool {
	metrics.IngestReceivedTotal.WithLabelValues(transport).Inc()
	events := li.srv.parser.ParseLine(line)
	if len(events) == 0 {
		events = []models.LogEvent{li.srv.parser.ParseRaw(line)}
	}
	ok := true
	for _, ev := range events {
		if !li.pool.TrySubmit(ev) {
			metrics.IngestDroppedTotal.WithLabelValues(transport).Inc()
			ok = false
		}
	}
	return ok
}

// Close stops accepting lines and waits for queued ones to be recorded.
func (li *LiveIngest) Close() {
	li.pool.Close()
	li.done.Wait()
}
