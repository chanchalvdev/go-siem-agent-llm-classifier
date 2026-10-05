package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/chverma/siemagent/internal/ioc"
)

// WithWatchlists matches every event against IOC watchlists.
func WithWatchlists(svc *ioc.Service) ServerOption {
	return func(srv *Server) { srv.watchlists = svc }
}

func (s *Server) requireWatchlists(w http.ResponseWriter) bool {
	if s.watchlists == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "watchlists are not enabled"})
		return false
	}
	return true
}

func (s *Server) handleListWatchlists(w http.ResponseWriter, _ *http.Request) {
	if !s.requireWatchlists(w) {
		return
	}
	writeJSON(w, http.StatusOK, s.watchlists.List())
}

func (s *Server) handleCreateWatchlist(w http.ResponseWriter, r *http.Request) {
	if !s.requireWatchlists(w) {
		return
	}
	var req ioc.NewWatchlist
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	wl, err := s.watchlists.Create(r.Context(), actor(r), req)
	if s.watchlistError(w, err) {
		return
	}
	// A new feed is downloaded by the service's refresh loop within a
	// minute; POST /refresh fetches it at once.
	writeJSON(w, http.StatusCreated, wl)
}

func (s *Server) handleUpdateWatchlist(w http.ResponseWriter, r *http.Request) {
	if !s.requireWatchlists(w) {
		return
	}
	var req ioc.Update
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	wl, err := s.watchlists.Update(r.Context(), chi.URLParam(r, "id"), req)
	if s.watchlistError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, wl)
}

func (s *Server) handleDeleteWatchlist(w http.ResponseWriter, r *http.Request) {
	if !s.requireWatchlists(w) {
		return
	}
	if s.watchlistError(w, s.watchlists.Delete(r.Context(), chi.URLParam(r, "id"))) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRefreshWatchlist(w http.ResponseWriter, r *http.Request) {
	if !s.requireWatchlists(w) {
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.watchlists.Refresh(r.Context(), id); err != nil {
		if errors.Is(err, ioc.ErrNotFound) || errors.Is(err, ioc.ErrReadOnly) {
			s.watchlistError(w, err)
			return
		}
		// The download failed; the list keeps its previous indicators and
		// records the error, which the response shows.
	}
	wl, err := s.watchlists.Get(id)
	if s.watchlistError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, wl)
}

type indicatorPage struct {
	Total      int             `json:"total"`
	Indicators []ioc.Indicator `json:"indicators"`
}

func (s *Server) handleListIndicators(w http.ResponseWriter, r *http.Request) {
	if !s.requireWatchlists(w) {
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 5000 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be 1–5000"})
			return
		}
		limit = n
	}
	inds, total, err := s.watchlists.Indicators(chi.URLParam(r, "id"), limit)
	if s.watchlistError(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, indicatorPage{Total: total, Indicators: inds})
}

type addIndicatorsRequest struct {
	Values []string `json:"values"`
	Note   string   `json:"note"`
}

type addIndicatorsResponse struct {
	Added    []ioc.Indicator `json:"added"`
	Rejected []string        `json:"rejected"`
}

func (s *Server) handleAddIndicators(w http.ResponseWriter, r *http.Request) {
	if !s.requireWatchlists(w) {
		return
	}
	var req addIndicatorsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	added, rejected, err := s.watchlists.AddIndicators(r.Context(), chi.URLParam(r, "id"), actor(r), req.Note, req.Values)
	if s.watchlistError(w, err) {
		return
	}
	if added == nil {
		added = []ioc.Indicator{}
	}
	if rejected == nil {
		rejected = []string{}
	}
	writeJSON(w, http.StatusOK, addIndicatorsResponse{Added: added, Rejected: rejected})
}

// handleRemoveIndicator takes the value as ?value= because ranges contain "/".
func (s *Server) handleRemoveIndicator(w http.ResponseWriter, r *http.Request) {
	if !s.requireWatchlists(w) {
		return
	}
	value := strings.TrimSpace(r.URL.Query().Get("value"))
	if value == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "value is required"})
		return
	}
	if s.watchlistError(w, s.watchlists.RemoveIndicator(r.Context(), chi.URLParam(r, "id"), value)) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLookupIOC(w http.ResponseWriter, r *http.Request) {
	if !s.requireWatchlists(w) {
		return
	}
	value := strings.TrimSpace(r.URL.Query().Get("value"))
	if value == "" || len(value) > 2048 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "value is required"})
		return
	}
	res := s.watchlists.Lookup(value)
	if res == nil {
		res = []ioc.LookupResult{}
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) watchlistError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ioc.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, ioc.ErrInvalid):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": strings.TrimPrefix(err.Error(), ioc.ErrInvalid.Error()+": ")})
	case errors.Is(err, ioc.ErrReadOnly):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	default:
		slog.Error("watchlist operation failed", "component", "api", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "the watchlist store is unavailable"})
	}
	return true
}
