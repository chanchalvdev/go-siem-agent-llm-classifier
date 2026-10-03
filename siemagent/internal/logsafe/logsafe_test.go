package logsafe

import (
	"errors"
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	got := String("ok\nlevel=ERROR msg=forged\r\x1b[31m")
	if strings.ContainsAny(got, "\n\r\x1b") || got != "ok level=ERROR msg=forged [31m" {
		t.Fatalf("got %q", got)
	}
	if long := String(strings.Repeat("a", 1000)); len(long) > maxLen+len("…") {
		t.Fatalf("not capped: %d", len(long))
	}
	if Err(errors.New("a\nb")) != "a b" || Err(nil) != "" {
		t.Fatal("Err")
	}
}
