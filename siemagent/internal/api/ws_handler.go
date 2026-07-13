package api

import (
	"log/slog"
	"net/http"

	"github.com/gorilla/websocket"
)

// upgrader promotes an HTTP request to a WebSocket. Origin checks are handled by
// the CORS middleware, so CheckOrigin stays permissive here.
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(*http.Request) bool { return true },
}

// handleAlertStream upgrades the connection, registers it with the hub, and
// blocks reading (to detect disconnect) until the client goes away.
func (s *Server) handleAlertStream(w http.ResponseWriter, r *http.Request) {
	if s.hub == nil {
		http.Error(w, "alert stream not enabled", http.StatusServiceUnavailable)
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Warn("ws upgrade failed", "component", "api", "error", err)
		return
	}
	id := s.hub.Register(conn)
	defer s.hub.Unregister(id)

	// Block on reads so we notice when the client disconnects. We ignore
	// inbound payloads — this stream is server-to-client only.
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return
		}
	}
}
