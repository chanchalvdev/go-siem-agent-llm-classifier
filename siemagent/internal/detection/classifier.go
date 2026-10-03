package detection

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/chverma/siemagent/internal/classifier"
	"github.com/chverma/siemagent/internal/metrics"
	"github.com/chverma/siemagent/internal/models"
)

// Mode controls how rules and the LLM combine.
type Mode string

const (
	// ModeRulesFirst classifies rule matches from the rule alone and sends
	// only unmatched events to the LLM — the cheapest, fastest setting.
	ModeRulesFirst Mode = "rules-first"
	// ModeEnrich always asks the LLM and attaches matching rules; the rule's
	// severity wins when it is higher.
	ModeEnrich Mode = "enrich"
	// ModeOff disables rule evaluation.
	ModeOff Mode = "off"
)

// ParseMode validates a DETECTION_MODE value ("" means rules-first).
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case "", ModeRulesFirst:
		return ModeRulesFirst, nil
	case ModeEnrich, ModeOff:
		return Mode(s), nil
	}
	return "", fmt.Errorf("unknown DETECTION_MODE %q (want rules-first, enrich or off)", s)
}

// Classifier wraps an LLM classifier with rule evaluation. It implements
// classifier.Interface, so the API, worker pool and CLI use it unchanged.
type Classifier struct {
	next   classifier.Interface
	engine *Engine
	mode   Mode
	// index stores rule-only verdicts for semantic search; the LLM
	// classifier indexes its own results. May be nil.
	index func(models.ClassifiedEvent)
}

var _ classifier.Interface = (*Classifier)(nil)

func NewClassifier(next classifier.Interface, engine *Engine, mode Mode, index func(models.ClassifiedEvent)) *Classifier {
	return &Classifier{next: next, engine: engine, mode: mode, index: index}
}

func (c *Classifier) Classify(ctx context.Context, ev models.LogEvent) (models.ClassifiedEvent, error) {
	return c.ClassifyStream(ctx, ev, nil)
}

func (c *Classifier) ClassifyStream(ctx context.Context, ev models.LogEvent, onChunk func(string)) (models.ClassifiedEvent, error) {
	if c.mode == ModeOff || c.engine == nil {
		return c.next.ClassifyStream(ctx, ev, onChunk)
	}

	dets := c.engine.Match(ev)
	if c.mode == ModeRulesFirst && len(dets) > 0 {
		metrics.LLMCallsSavedTotal.Inc()
		out := c.engine.Verdict(ev, dets)
		if c.index != nil {
			c.index(out)
		}
		return out, nil
	}

	out, err := c.next.ClassifyStream(ctx, ev, onChunk)
	if err != nil {
		if len(dets) > 0 {
			// The rules already know what this is; don't lose the alert
			// because the LLM is down.
			slog.Warn("LLM classification failed, using rule verdict",
				"component", "detection", "rule", dets[0].RuleID, "error", err)
			out := c.engine.Verdict(ev, dets)
			if c.index != nil {
				c.index(out)
			}
			return out, nil
		}
		return out, err
	}
	if len(dets) > 0 {
		out.Detections = dets
		out.ClassifiedBy = models.ClassifiedByBoth
		if rs := SeverityForLevel(dets[0].Level); severityRank(rs) < severityRank(out.Severity) {
			out.Severity = rs
		}
	}
	return out, nil
}

func (c *Classifier) Ping(ctx context.Context) error { return c.next.Ping(ctx) }

// severityRank orders P1 (most severe) to P5; unknown sorts last.
func severityRank(s models.Severity) int {
	switch s {
	case models.SeverityP1:
		return 1
	case models.SeverityP2:
		return 2
	case models.SeverityP3:
		return 3
	case models.SeverityP4:
		return 4
	case models.SeverityP5:
		return 5
	}
	return 6
}
