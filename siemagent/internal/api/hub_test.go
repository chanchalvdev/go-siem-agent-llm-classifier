package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// wsTestServer starts an httptest server exposing only the alert-stream route
// backed by a fresh hub, and returns the hub and a ws:// dial URL.
func wsTestServer(t *testing.T) (*Hub, string) {
	t.Helper()
	s := &Server{hub: NewHub()}
	srv := httptest.NewServer(http.HandlerFunc(s.handleAlertStream))
	t.Cleanup(srv.Close)
	return s.hub, "ws" + strings.TrimPrefix(srv.URL, "http")
}

func dial(t *testing.T, url string) *websocket.Conn {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func expectMessage(t *testing.T, conn *websocket.Conn, want string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(msg) != want {
		t.Fatalf("got %q, want %q", msg, want)
	}
}

func TestHubBroadcast(t *testing.T) {
	hub, url := wsTestServer(t)
	conns := []*websocket.Conn{dial(t, url), dial(t, url), dial(t, url)}

	waitClients(t, hub, 3)
	hub.Broadcast([]byte("hello"))
	for _, c := range conns {
		expectMessage(t, c, "hello")
	}
}

func TestHubDisconnectNoPanic(t *testing.T) {
	hub, url := wsTestServer(t)
	c1, c2, c3 := dial(t, url), dial(t, url), dial(t, url)
	waitClients(t, hub, 3)

	_ = c2.Close()
	waitClients(t, hub, 2)

	hub.Broadcast([]byte("after"))
	expectMessage(t, c1, "after")
	expectMessage(t, c3, "after")
}

func TestHubSendTargeted(t *testing.T) {
	hub, url := wsTestServer(t)
	dial(t, url)
	c2 := dial(t, url)
	waitClients(t, hub, 2)

	// Client IDs are assigned in dial order starting at "1".
	hub.Send("2", []byte("just-you"))
	expectMessage(t, c2, "just-you")
}

// waitClients polls until the hub reports the expected client count.
func waitClients(t *testing.T, hub *Hub, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		hub.mu.RLock()
		got := len(hub.clients)
		hub.mu.RUnlock()
		if got == n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("hub did not reach %d clients", n)
}
