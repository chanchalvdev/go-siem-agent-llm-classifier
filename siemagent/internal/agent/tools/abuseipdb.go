// Package tools holds concrete agent.Tool implementations.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

const (
	abuseEndpoint  = "https://api.abuseipdb.com/api/v2/check"
	abuseDayBudget = 3000
)

// AbuseIPDB looks up an IP's reputation via the AbuseIPDB API.
type AbuseIPDB struct {
	apiKey  string
	baseURL string
	client  *http.Client
	calls   atomic.Int64
}

// NewAbuseIPDB builds the tool. apiKey may be empty (tool degrades gracefully);
// client may be nil (a 10s-timeout default is used).
func NewAbuseIPDB(apiKey string, client *http.Client) *AbuseIPDB {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &AbuseIPDB{apiKey: apiKey, baseURL: abuseEndpoint, client: client}
}

func (a *AbuseIPDB) Name() string        { return "check_abuseipdb" }
func (a *AbuseIPDB) Description() string { return "Look up an IP address reputation and abuse score." }
func (a *AbuseIPDB) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"ip":{"type":"string","description":"IPv4 or IPv6 address"}},"required":["ip"]}`)
}

func note(ip, msg string) (string, error) {
	b, _ := json.Marshal(map[string]string{"ip": ip, "note": msg})
	return string(b), nil
}

// Execute performs the lookup, guarding against SSRF and missing config.
func (a *AbuseIPDB) Execute(ctx context.Context, input json.RawMessage) (string, error) {
	var in struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("abuseipdb: bad input: %w", err)
	}
	ip := net.ParseIP(in.IP)
	if ip == nil {
		return "", fmt.Errorf("abuseipdb: %q is not a valid IP", in.IP)
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return note(in.IP, "private IP, skipping lookup")
	}
	if a.apiKey == "" {
		return note(in.IP, "ABUSEIPDB_KEY not set")
	}
	if a.calls.Load() >= abuseDayBudget {
		return note(in.IP, "daily AbuseIPDB budget exhausted")
	}
	return a.fetch(ctx, in.IP)
}

func (a *AbuseIPDB) fetch(ctx context.Context, ip string) (string, error) {
	u := fmt.Sprintf("%s?ipAddress=%s&maxAgeInDays=90", a.baseURL, url.QueryEscape(ip))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", fmt.Errorf("abuseipdb: %w", err)
	}
	req.Header.Set("Key", a.apiKey)
	req.Header.Set("Accept", "application/json")

	a.calls.Add(1)
	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("abuseipdb: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("abuseipdb: status %d", resp.StatusCode)
	}

	var body struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			ISP                  string `json:"isp"`
			TotalReports         int    `json:"totalReports"`
			LastReportedAt       string `json:"lastReportedAt"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("abuseipdb: decode: %w", err)
	}
	out, _ := json.Marshal(map[string]any{
		"ip":            ip,
		"abuse_score":   body.Data.AbuseConfidenceScore,
		"country":       body.Data.CountryCode,
		"isp":           body.Data.ISP,
		"total_reports": body.Data.TotalReports,
		"last_reported": body.Data.LastReportedAt,
	})
	return string(out), nil
}
