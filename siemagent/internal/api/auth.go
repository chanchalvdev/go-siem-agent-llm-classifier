package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"

	"github.com/chverma/siemagent/internal/metrics"
)

// apiKeyAuth rejects requests without a valid API key. Keys are accepted as
// "Authorization: Bearer <key>" or "X-API-Key: <key>". Browsers cannot set
// headers on a WebSocket handshake, so upgrades may pass ?api_key=<key>
// instead; plain HTTP requests may not, which keeps keys out of URLs and logs.
//
// With no keys configured every request passes (local development).
func apiKeyAuth(keys []string) func(http.Handler) http.Handler {
	if len(keys) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	// Compare fixed-length digests so the comparison leaks neither key
	// contents nor key length through timing.
	digests := make([][32]byte, len(keys))
	for i, k := range keys {
		digests[i] = sha256.Sum256([]byte(k))
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if validKey(requestKey(r), digests) {
				next.ServeHTTP(w, r)
				return
			}
			metrics.AuthFailuresTotal.Inc()
			w.Header().Set("WWW-Authenticate", `Bearer realm="siemagent"`)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing or invalid API key"})
		})
	}
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

func validKey(key string, digests [][32]byte) bool {
	if key == "" {
		return false
	}
	got := sha256.Sum256([]byte(key))
	ok := 0
	for _, d := range digests {
		ok |= subtle.ConstantTimeCompare(got[:], d[:])
	}
	return ok == 1
}
