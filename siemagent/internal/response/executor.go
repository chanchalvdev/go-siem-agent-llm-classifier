package response

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/chverma/siemagent/internal/incident"
)

// Executor carries out an approved action.
type Executor interface {
	Execute(ctx context.Context, a Action, spec ActionSpec, inc incident.Incident) (result string, err error)
}

// Connectors configures where actions are sent.
type Connectors struct {
	// ContainmentURL receives block_ip, disable_user and isolate_host as JSON.
	// Point it at your automation (n8n, Tines, Shuffle, an AWX job, a Lambda)
	// that talks to the firewall, IdP or EDR.
	ContainmentURL string
	// SlackURL is a Slack incoming-webhook URL used by notify actions.
	SlackURL string
}

// HTTPExecutor runs actions by calling webhooks.
type HTTPExecutor struct {
	conn   Connectors
	client *http.Client
}

func NewHTTPExecutor(conn Connectors) *HTTPExecutor {
	return &HTTPExecutor{conn: conn, client: &http.Client{
		Timeout: 10 * time.Second,
		// Never follow redirects: an approved action must go only where it
		// was configured to go.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// ContainmentRequest is the JSON body sent to the containment webhook.
type ContainmentRequest struct {
	Action        string `json:"action"` // block_ip | disable_user | isolate_host
	Target        string `json:"target"`
	ActionID      string `json:"action_id"`
	IncidentID    string `json:"incident_id"`
	IncidentTitle string `json:"incident_title"`
	Severity      string `json:"severity"`
	Playbook      string `json:"playbook"`
	ApprovedBy    string `json:"approved_by"`
}

func (x *HTTPExecutor) Execute(ctx context.Context, a Action, spec ActionSpec, inc incident.Incident) (string, error) {
	switch a.Type {
	case ActionBlockIP, ActionDisableUser, ActionIsolateHost:
		if x.conn.ContainmentURL == "" {
			return "", errors.New("RESPONSE_WEBHOOK_URL is not set, so containment actions cannot run")
		}
		return x.post(ctx, x.conn.ContainmentURL, ContainmentRequest{
			Action: a.Type, Target: a.Target, ActionID: a.ID, IncidentID: inc.ID,
			IncidentTitle: inc.Title, Severity: string(inc.Severity), Playbook: a.PlaybookID, ApprovedBy: a.DecidedBy,
		})
	case ActionNotify:
		if x.conn.SlackURL == "" {
			return "", errors.New("SLACK_WEBHOOK_URL is not set, so notifications cannot be sent")
		}
		return x.post(ctx, x.conn.SlackURL, map[string]string{"text": a.Message})
	case ActionWebhook:
		return x.post(ctx, spec.URL, map[string]any{
			"action_id": a.ID, "playbook": a.PlaybookID, "message": a.Message, "approved_by": a.DecidedBy,
			"incident": map[string]any{
				"id": inc.ID, "title": inc.Title, "severity": inc.Severity, "status": inc.Status,
				"entities": inc.Entities, "tactics": inc.Tactics, "alert_count": inc.AlertCount,
			},
		})
	}
	return "", fmt.Errorf("unknown action type %q", a.Type)
}

func (x *HTTPExecutor) post(ctx context.Context, url string, body any) (string, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "siemagent-response/1")
	resp, err := x.client.Do(req)
	if err != nil {
		// The URL can carry a token (Slack webhooks do), so report only the host.
		return "", fmt.Errorf("call %s: %w", hostOf(url), errors.Unwrap(err))
	}
	defer func() { _ = resp.Body.Close() }()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	msg := strings.TrimSpace(string(snippet))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("%s answered HTTP %d: %s", hostOf(url), resp.StatusCode, msg)
	}
	result := fmt.Sprintf("%s answered HTTP %d", hostOf(url), resp.StatusCode)
	if msg != "" {
		result += ": " + msg
	}
	return result, nil
}

func hostOf(url string) string {
	rest := url
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	return rest
}
