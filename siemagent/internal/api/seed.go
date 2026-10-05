package api

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// maxSeedLines bounds a seed file; it is for demos and fixtures, not bulk import.
const maxSeedLines = 10_000

// Seed replays a log file through the normal pipeline (detect, classify,
// store, correlate, respond) when no events are stored yet, so a fresh demo
// starts with incidents to look at. Lines are processed in order, one at a
// time, so threshold rules and correlation see them as they would live.
// Blank lines and lines starting with # are skipped. It returns how many
// events were recorded; 0 with a nil error means the store already had data.
func (s *Server) Seed(ctx context.Context, path string) (int, error) {
	existing, err := s.events.Recent(ctx, 1)
	if err != nil {
		return 0, fmt.Errorf("seed: check existing events: %w", err)
	}
	if len(existing) > 0 {
		return 0, nil
	}
	f, err := os.Open(path) //nolint:gosec // path comes from the operator's SEED_LOG_FILE
	if err != nil {
		return 0, fmt.Errorf("seed: %w", err)
	}
	defer func() { _ = f.Close() }()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(lines) == maxSeedLines {
			return 0, fmt.Errorf("seed: %s has more than %d log lines", path, maxSeedLines)
		}
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("seed: read %s: %w", path, err)
	}

	n := 0
	for _, line := range lines {
		for _, ev := range s.parser.ParseLineWithFormat(line, "auto") {
			if ctx.Err() != nil {
				return n, ctx.Err()
			}
			classified, err := s.classifier.Classify(ctx, ev)
			if err != nil {
				slog.Warn("seed: classification failed", "component", "api", "error", err)
				continue
			}
			s.record(classified)
			n++
		}
	}
	return n, nil
}
