package ingest

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type collector struct {
	mu    sync.Mutex
	lines []string
}

func (c *collector) handle(transport, line string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, transport+"|"+line)
}

func (c *collector) waitFor(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		if len(c.lines) >= n {
			out := slices.Clone(c.lines)
			c.mu.Unlock()
			slices.Sort(out)
			return out
		}
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t.Fatalf("timed out waiting for %d lines, got %q", n, c.lines)
	return nil
}

func TestSyslogUDPAndTCP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &collector{}
	l, err := ListenSyslog(ctx, "127.0.0.1:0", "127.0.0.1:0", c.handle)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	udp, err := net.Dial("udp", l.UDPAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	// One datagram carrying two messages plus blank noise.
	if _, err := udp.Write([]byte("<34>Oct 11 22:14:15 host sshd: one\n\n<34>Oct 11 22:14:16 host sshd: two\r\n")); err != nil {
		t.Fatal(err)
	}

	tcp, err := net.Dial("tcp", l.TCPAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tcp.Write([]byte("<34>1 2024-01-15T10:30:00Z h app 1 - three\r\n<34>1 2024-01-15T10:30:01Z h app 1 - four\n")); err != nil {
		t.Fatal(err)
	}

	got := c.waitFor(t, 4)
	want := []string{
		"tcp|<34>1 2024-01-15T10:30:00Z h app 1 - three",
		"tcp|<34>1 2024-01-15T10:30:01Z h app 1 - four",
		"udp|<34>Oct 11 22:14:15 host sshd: one",
		"udp|<34>Oct 11 22:14:16 host sshd: two",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("lines:\n got  %q\n want %q", got, want)
	}

	// Cancelling must close sockets and open connections so Wait returns.
	cancel()
	done := make(chan struct{})
	go func() { l.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("listener did not shut down")
	}
	_ = tcp.Close()
}

func TestSyslogOversizedTCPLineDropsConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &collector{}
	l, err := ListenSyslog(ctx, "", "127.0.0.1:0", c.handle)
	if err != nil {
		t.Fatal(err)
	}
	if l.UDPAddr() != nil {
		t.Fatal("UDP should be disabled")
	}

	conn, err := net.Dial("tcp", l.TCPAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte(strings.Repeat("A", maxMessage+10) + "\n"))

	// The server closes the connection instead of buffering without bound.
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the server to close an oversized connection")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.lines) != 0 {
		t.Fatalf("oversized line must not be emitted, got %d lines", len(c.lines))
	}
}

func TestListenSyslogNeedsAnAddress(t *testing.T) {
	if _, err := ListenSyslog(context.Background(), "", "", func(string, string) {}); err == nil {
		t.Fatal("expected an error with no addresses")
	}
}
