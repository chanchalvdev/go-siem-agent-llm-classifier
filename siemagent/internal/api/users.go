package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/chverma/siemagent/internal/auth"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// handleLogin checks credentials and sets the session cookie.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.users == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user accounts are not enabled"})
		return
	}
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	token, u, err := s.users.Login(r.Context(), req.Username, req.Password, clientIP(r))
	switch {
	case errors.Is(err, auth.ErrLocked):
		w.Header().Set("Retry-After", "900")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": err.Error()})
		return
	case errors.Is(err, auth.ErrBadCredentials):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	case err != nil:
		slog.Error("login failed", "component", "api", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "login is unavailable"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/",
		Expires:  time.Now().Add(s.users.SessionTTL()),
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: s.cfg.CookieSecure || r.TLS != nil,
	})
	writeJSON(w, http.StatusOK, Principal{Name: u.Username, Role: u.Role, Kind: "session", UserID: u.ID})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && s.users != nil {
		if err := s.users.Logout(r.Context(), c.Value, actor(r)); err != nil {
			slog.Error("logout failed", "component", "api", "error", err)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: s.cfg.CookieSecure || r.TLS != nil})
	w.WriteHeader(http.StatusNoContent)
}

// handleMe tells the dashboard who is logged in and what they may do.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"username": p.Name, "role": p.Role, "auth": p.Kind, "id": p.UserID,
		"permissions": map[string]bool{
			"read": p.Role.Can(auth.PermRead), "write": p.Role.Can(auth.PermWrite), "admin": p.Role.Can(auth.PermAdmin),
		},
	})
}

type passwordRequest struct {
	Current string `json:"current_password"`
	New     string `json:"new_password"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFrom(r.Context())
	if s.users == nil || p.Kind != "session" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "only logged-in users can change their password"})
		return
	}
	var req passwordRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if s.authError(w, s.users.ChangePassword(r.Context(), p.UserID, req.Current, req.New)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) requireUsers(w http.ResponseWriter) bool {
	if s.users == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user accounts are not enabled"})
		return false
	}
	return true
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if !s.requireUsers(w) {
		return
	}
	list, err := s.users.ListUsers(r.Context())
	if s.authError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireUsers(w) {
		return
	}
	var in auth.NewUser
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	u, err := s.users.CreateUser(r.Context(), actor(r), in)
	if s.authError(w, err) {
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if !s.requireUsers(w) {
		return
	}
	var up auth.UserUpdate
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&up); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	u, err := s.users.UpdateUser(r.Context(), actor(r), chi.URLParam(r, "id"), up)
	if s.authError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	if !s.requireUsers(w) {
		return
	}
	f := auth.AuditFilter{Actor: r.URL.Query().Get("actor"), Limit: 200}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be 1–1000"})
			return
		}
		f.Limit = n
	}
	list, err := s.users.ListAudit(r.Context(), f)
	if s.authError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) authError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, auth.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
	case errors.Is(err, auth.ErrInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": strings.TrimPrefix(err.Error(), auth.ErrInvalid.Error()+": ")})
	default:
		slog.Error("account operation failed", "component", "api", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "the account store is unavailable"})
	}
	return true
}

// unaudited lists high-volume ingestion routes left out of the audit log;
// it records who changed or approved what, not every classified log line.
var unaudited = map[string]bool{
	"/api/classify": true, "/api/classify/stream": true, "/api/ingest": true,
	"/classify": true, "/classify/stream": true,
}

// auditTrail records every state-changing API call: who, what route, which
// resource and the outcome. Runs inside authentication.
func (s *Server) auditTrail(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.users == nil || safeMethod(r.Method) || unaudited[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		rec := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(rec, r)
		route := r.URL.Path
		if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
			route = rc.RoutePattern()
		}
		status := rec.Status()
		if status == 0 {
			status = http.StatusOK
		}
		s.users.Audit(r.Context(), auth.AuditEntry{
			Actor: actor(r), Action: r.Method + " " + route, Target: r.URL.Path, Status: status, IP: clientIP(r),
		})
	})
}
