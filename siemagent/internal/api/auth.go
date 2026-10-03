package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"

	"github.com/chverma/siemagent/internal/auth"
	"github.com/chverma/siemagent/internal/metrics"
)

// sessionCookie holds the dashboard login session token.
const sessionCookie = "siem_session"

// csrfHeader must accompany state-changing requests authenticated by the
// session cookie. Browsers cannot add custom headers to cross-site requests
// without a CORS preflight (which only allows our origin), so a forged form
// or image request from another site is rejected even if the cookie is sent.
const csrfHeader = "X-Requested-With"

// Principal is who is making a request.
type Principal struct {
	Name   string    `json:"username"`
	Role   auth.Role `json:"role"`
	Kind   string    `json:"auth"` // "session" | "api_key" | "open"
	UserID string    `json:"id,omitempty"`
}

type principalKey struct{}

func principalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}

// actor names who made a change, for incident history and the audit log.
func actor(r *http.Request) string {
	if p, ok := principalFrom(r.Context()); ok && p.Name != "" {
		return p.Name
	}
	return "analyst"
}

// WithUsers enables user accounts, sessions and the audit log.
func WithUsers(svc *auth.Service) ServerOption {
	return func(srv *Server) { srv.users = svc }
}

// keyDigests hashes the configured API keys once.
func keyDigests(keys []string) [][32]byte {
	digests := make([][32]byte, len(keys))
	for i, k := range keys {
		digests[i] = sha256.Sum256([]byte(k))
	}
	return digests
}

// openMode reports whether the deployment has no authentication at all
// (no API keys and no user accounts): local development only.
func (s *Server) openMode() bool {
	return len(s.cfg.APIKeys) == 0 && (s.users == nil || !s.users.UsersEnabled())
}

// authenticate identifies the caller from an API key, a session cookie or,
// on an unauthenticated development install, nobody (open mode, full
// access). Unidentified requests get 401.
//
// API keys are accepted as "Authorization: Bearer <key>" or "X-API-Key:
// <key>". Browsers cannot set headers on a WebSocket handshake, so upgrades
// may pass ?api_key=<key> instead; plain HTTP requests may not, which keeps
// keys out of URLs and logs. API keys act as admin service accounts.
func (s *Server) authenticate(next http.Handler) http.Handler {
	digests := keyDigests(s.cfg.APIKeys)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.identify(r, digests)
		if !ok {
			metrics.AuthFailuresTotal.Inc()
			w.Header().Set("WWW-Authenticate", `Bearer realm="siemagent"`)
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error": "authentication required", "login_required": s.users != nil && s.users.UsersEnabled(),
			})
			return
		}
		if p.Kind == "session" && !safeMethod(r.Method) && r.Header.Get(csrfHeader) == "" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing " + csrfHeader + " header"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}

func (s *Server) identify(r *http.Request, digests [][32]byte) (Principal, bool) {
	if key := requestKey(r); key != "" {
		if i := matchKey(key, digests); i >= 0 {
			return Principal{Name: keyName(key), Role: auth.RoleAdmin, Kind: "api_key"}, true
		}
		return Principal{}, false
	}
	if s.users != nil {
		if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
			if u, err := s.users.Authenticate(r.Context(), c.Value); err == nil {
				return Principal{Name: u.Username, Role: u.Role, Kind: "session", UserID: u.ID}, true
			}
		}
	}
	if s.openMode() {
		return Principal{Name: "analyst", Role: auth.RoleAdmin, Kind: "open"}, true
	}
	return Principal{}, false
}

// keyName labels an API key in audit records without revealing it.
func keyName(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "api-key-" + hex.EncodeToString(sum[:3])
}

// require rejects callers whose role lacks the permission.
func require(perm auth.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, _ := principalFrom(r.Context())
			if !p.Role.Can(perm) {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error": "your role (" + string(p.Role) + ") cannot do this; it needs " + perm.String() + " access",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requireByMethod needs read access for safe methods and write access for
// everything else; admin-only routes add require(auth.PermAdmin).
func requireByMethod(next http.Handler) http.Handler {
	read, write := require(auth.PermRead)(next), require(auth.PermWrite)(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if safeMethod(r.Method) {
			read.ServeHTTP(w, r)
			return
		}
		write.ServeHTTP(w, r)
	})
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func requestKey(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		if token, ok := strings.CutPrefix(h, "Bearer "); ok {
			return strings.TrimSpace(token)
		}
	}
	if k := r.Header.Get("X-API-Key"); k != "" {
		return k
	}
	if websocket.IsWebSocketUpgrade(r) {
		return r.URL.Query().Get("api_key")
	}
	return ""
}

// matchKey returns the index of the matching key, or -1. Fixed-length
// digests are compared in constant time, leaking neither key contents nor
// length; every key is checked so timing doesn't reveal which one matched.
func matchKey(key string, digests [][32]byte) int {
	if key == "" {
		return -1
	}
	got := sha256.Sum256([]byte(key))
	found := -1
	for i, d := range digests {
		if subtle.ConstantTimeCompare(got[:], d[:]) == 1 {
			found = i
		}
	}
	return found
}

// clientIP is the TCP peer address (X-Forwarded-For is deliberately not
// trusted; see buildRouter).
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
