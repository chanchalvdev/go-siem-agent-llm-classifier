package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const otxBase = "https://otx.alienvault.com/api/v1/indicators"

// otxPaths maps an indicator type to its OTX URL section.
var otxPaths = map[string]string{"ip": "IPv4", "domain": "domain", "hash": "file"}

// otxPulse is one OTX pulse (threat report) referencing the indicator.
type otxPulse struct {
	Name      string   `json:"name"`
	Created   string   `json:"created"`
	Tags      []string `json:"tags"`
	Adversary string   `json:"adversary"`
}

// OTX looks up threat intel for an indicator via AlienVault OTX.
type OTX struct {
	apiKey  string
	baseURL string
	client  *http.Client
}

// NewOTX builds the tool. apiKey may be empty (degrades gracefully); client may
// be nil (a 10s-timeout default is used).
func NewOTX(apiKey string, client *http.Client) *OTX {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &OTX{apiKey: apiKey, baseURL: otxBase, client: client}
}

func (o *OTX) Name() string        { return "check_otx" }
func (o *OTX) Description() string { return "Look up AlienVault OTX threat intel for an indicator." }
func (o *OTX) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"indicator":{"type":"string"},"type":{"type":"string","enum":["ip","domain","hash"]}},"required":["indicator","type"]}`)
}

// Execute validates the indicator, then queries OTX for its pulse info.
func (o *OTX) Execute(ctx context.Context, input json.RawMessage) (string, error) {
	var in struct {
		Indicator string `json:"indicator"`
		Type      string `json:"type"`
	}
	if err := json.Unmarshal(input, &in); err != nil {
		return "", fmt.Errorf("otx: bad input: %w", err)
	}
	section, ok := otxPaths[in.Type]
	if !ok {
		return "", fmt.Errorf("otx: unsupported type %q", in.Type)
	}
	if in.Type == "ip" {
		ip := net.ParseIP(in.Indicator)
		if ip == nil {
			return "", fmt.Errorf("otx: %q is not a valid IP", in.Indicator)
		}
		if ip.IsPrivate() || ip.IsLoopback() {
			return note(in.Indicator, "private IP, skipping lookup")
		}
	}
	if o.apiKey == "" {
		return note(in.Indicator, "OTX_API_KEY not set")
	}
	return o.fetch(ctx, section, in.Indicator)
}

func (o *OTX) fetch(ctx context.Context, section, indicator string) (string, error) {
	u := fmt.Sprintf("%s/%s/%s/general", o.baseURL, section, url.PathEscape(indicator))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", fmt.Errorf("otx: %w", err)
	}
	req.Header.Set("X-OTX-API-KEY", o.apiKey)

	resp, err := o.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("otx: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("otx: status %d", resp.StatusCode)
	}

	var body struct {
		PulseInfo struct {
			Count  int        `json:"count"`
			Pulses []otxPulse `json:"pulses"`
		} `json:"pulse_info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("otx: decode: %w", err)
	}
	return summarize(indicator, body.PulseInfo.Count, body.PulseInfo.Pulses), nil
}

// summarize builds a compact JSON string from the pulse list.
func summarize(indicator string, count int, pulses []otxPulse) string {
	labels := map[string]bool{}
	recent, recentDate := "", ""
	for _, p := range pulses {
		for _, tag := range p.Tags {
			labels[strings.ToLower(tag)] = true
		}
		if p.Adversary != "" {
			labels[strings.ToLower(p.Adversary)] = true
		}
		if p.Created > recentDate {
			recent, recentDate = p.Name, p.Created
		}
	}
	tags := make([]string, 0, len(labels))
	for l := range labels {
		tags = append(tags, l)
	}
	out, _ := json.Marshal(map[string]any{
		"indicator":     indicator,
		"pulse_count":   count,
		"threat_labels": tags,
		"recent_pulse":  recent,
		"recent_date":   recentDate,
	})
	return string(out)
}
