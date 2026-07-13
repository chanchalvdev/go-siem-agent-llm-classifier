package api

import (
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
)

// sendBuffer is the per-client outbound queue depth. Full buffers drop messages
// rather than blocking a broadcast (a slow client must never stall the hub).
const sendBuffer = 256

// wsClient wraps a connection with its own buffered write channel.
type wsClient struct {
	id   string
	conn *websocket.Conn
	send chan []byte
}

// Hub fans messages out to all connected WebSocket clients.
type Hub struct {
	mu      sync.RWMutex
	clients map[string]*wsClient
	nextID  atomic.Int64
}

// NewHub returns an empty hub.
func NewHub() *Hub {
	return &Hub{clients: make(map[string]*wsClient)}
}

// Register adds a connection, starts its write pump, and returns its client ID.
func (h *Hub) Register(conn *websocket.Conn) string {
	id := strconv.FormatInt(h.nextID.Add(1), 10)
	c := &wsClient{id: id, conn: conn, send: make(chan []byte, sendBuffer)}
	h.mu.Lock()
	h.clients[id] = c
	h.mu.Unlock()
	go c.writePump()
	slog.Info("ws client registered", "component", "hub", "client", id)
	return id
}

// Unregister removes a client and closes its write channel.
func (h *Hub) Unregister(id string) {
	h.mu.Lock()
	c, ok := h.clients[id]
	if ok {
		delete(h.clients, id)
	}
	h.mu.Unlock()
	if ok {
		close(c.send)
		slog.Info("ws client unregistered", "component", "hub", "client", id)
	}
}

// Broadcast queues msg for every connected client (non-blocking per client).
func (h *Hub) Broadcast(msg []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, c := range h.clients {
		c.enqueue(msg)
	}
}

// Send queues msg for a single client by ID.
func (h *Hub) Send(id string, msg []byte) {
	h.mu.RLock()
	c, ok := h.clients[id]
	h.mu.RUnlock()
	if ok {
		c.enqueue(msg)
	}
}

// enqueue performs a non-blocking send; a full buffer drops the message.
func (c *wsClient) enqueue(msg []byte) {
	select {
	case c.send <- msg:
	default:
		slog.Warn("ws send buffer full, dropping", "component", "hub", "client", c.id)
	}
}

// writePump drains the send channel to the socket until it is closed.
func (c *wsClient) writePump() {
	for msg := range c.send {
		if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			break
		}
	}
	_ = c.conn.Close()
}
