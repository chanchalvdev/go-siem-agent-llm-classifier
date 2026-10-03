package api

import (
	"net/http"
)

// detectionRule is the API view of a loaded detection rule.
type detectionRule struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Level       string   `json:"level"`
	Status      string   `json:"status,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Source      string   `json:"source"`
	Hits        int64    `json:"hits"`
}

// handleDetectionRules lists loaded rules with their match counts since start.
func (s *Server) handleDetectionRules(w http.ResponseWriter, _ *http.Request) {
	out := []detectionRule{}
	if s.detections != nil {
		for _, r := range s.detections.Rules() {
			out = append(out, detectionRule{
				ID: r.ID, Title: r.Title, Description: r.Description, Level: r.Level,
				Status: r.Status, Tags: r.Tags, Source: r.Source, Hits: r.Hits(),
			})
		}
	}
	writeJSON(w, http.StatusOK, out)
}
