package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	openai "github.com/sashabaranov/go-openai"

	"github.com/chverma/siemagent/internal/agent"
	"github.com/chverma/siemagent/internal/config"
	"github.com/chverma/siemagent/internal/metrics"
	"github.com/chverma/siemagent/internal/models"
)

func TestInvestigationsAreCapped(t *testing.T) {
	// The client points nowhere; with every slot taken it must never be used.
	client := openai.NewClientWithConfig(openai.DefaultConfig("unused"))
	srv := New(config.Config{Port: "0"}, &mockClassifier{result: fixedResult},
		WithAgent(NewHub(), client, "model", agent.New()))

	for range maxConcurrentInvestigations {
		srv.agent.slots <- struct{}{}
	}

	before := testutil.ToFloat64(metrics.InvestigationsSkippedTotal)
	srv.maybeInvestigate(models.ClassifiedEvent{Severity: models.SeverityP1})
	srv.maybeInvestigate(models.ClassifiedEvent{Severity: models.SeverityP2})
	srv.maybeInvestigate(models.ClassifiedEvent{Severity: models.SeverityP4}) // not eligible

	if got := testutil.ToFloat64(metrics.InvestigationsSkippedTotal) - before; got != 2 {
		t.Fatalf("want 2 skipped investigations, got %v", got)
	}
	if len(srv.agent.slots) != maxConcurrentInvestigations {
		t.Fatalf("skipped investigations must not take or release slots, have %d", len(srv.agent.slots))
	}
}
