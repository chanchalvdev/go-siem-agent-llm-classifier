package api

import (
	"context"
	"testing"

	"github.com/chverma/siemagent/internal/config"
)

func TestLiveIngestRecordsSubmittedLines(t *testing.T) {
	srv := New(config.Config{Port: "0", Workers: 1}, &mockClassifier{result: fixedResult})
	li := srv.StartLiveIngest(context.Background())

	lines := []string{
		"<34>Oct 11 22:14:15 host sshd: Failed password for root from 10.0.0.9",
		"plain text that is not syslog",
	}
	for _, l := range lines {
		if !li.Submit("udp", l) {
			t.Fatalf("line dropped: %q", l)
		}
	}
	li.Close()

	got, err := srv.events.Recent(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(lines) {
		t.Fatalf("want %d recorded events, got %d", len(lines), len(got))
	}
	if li.Submit("udp", "after close") {
		t.Fatal("Submit after Close must report a drop")
	}
}
