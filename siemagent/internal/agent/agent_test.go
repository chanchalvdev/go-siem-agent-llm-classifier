package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	openai "github.com/sashabaranov/go-openai"

	"github.com/chverma/siemagent/internal/models"
)

// countingTool records how many times it was executed.
type countingTool struct{ calls atomic.Int64 }

func (c *countingTool) Name() string            { return "check_abuseipdb" }
func (c *countingTool) Description() string     { return "mock" }
func (c *countingTool) Schema() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }
func (c *countingTool) Execute(context.Context, json.RawMessage) (string, error) {
	c.calls.Add(1)
	return `{"abuse_score":90}`, nil
}

// mockLLM returns each queued response in order (last one repeats).
func mockLLM(t *testing.T, responses []openai.ChatCompletionResponse) *openai.Client {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		i := int(n.Add(1)) - 1
		if i >= len(responses) {
			i = len(responses) - 1
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(responses[i])
	}))
	t.Cleanup(srv.Close)
	cfg := openai.DefaultConfig("test")
	cfg.BaseURL = srv.URL
	return openai.NewClientWithConfig(cfg)
}

func toolCallResp() openai.ChatCompletionResponse {
	return openai.ChatCompletionResponse{Choices: []openai.ChatCompletionChoice{{
		FinishReason: openai.FinishReasonToolCalls,
		Message: openai.ChatCompletionMessage{
			Role: openai.ChatMessageRoleAssistant,
			ToolCalls: []openai.ToolCall{{
				ID:       "call_1",
				Type:     openai.ToolTypeFunction,
				Function: openai.FunctionCall{Name: "check_abuseipdb", Arguments: `{"ip":"8.8.8.8"}`},
			}},
		},
	}}}
}

func stopResp(text string) openai.ChatCompletionResponse {
	return openai.ChatCompletionResponse{Choices: []openai.ChatCompletionChoice{{
		FinishReason: openai.FinishReasonStop,
		Message:      openai.ChatCompletionMessage{Role: openai.ChatMessageRoleAssistant, Content: text},
	}}}
}

func regWithTool() (*Registry, *countingTool) {
	tool := &countingTool{}
	r := New()
	r.Register(tool)
	return r, tool
}

var sampleEvent = models.ClassifiedEvent{AttackType: "Brute Force", Severity: models.SeverityP1}

func TestRunIncidentToolThenStop(t *testing.T) {
	client := mockLLM(t, []openai.ChatCompletionResponse{toolCallResp(), stopResp("## Summary\nDone")})
	reg, tool := regWithTool()

	out, err := RunIncident(context.Background(), client, "m", reg, sampleEvent)
	if err != nil {
		t.Fatalf("RunIncident: %v", err)
	}
	if tool.calls.Load() != 1 {
		t.Fatalf("tool calls = %d, want 1", tool.calls.Load())
	}
	if !strings.Contains(out, "Summary") {
		t.Fatalf("unexpected playbook: %s", out)
	}
}

func TestRunIncidentImmediateStop(t *testing.T) {
	client := mockLLM(t, []openai.ChatCompletionResponse{stopResp("no tools needed")})
	reg, tool := regWithTool()

	if _, err := RunIncident(context.Background(), client, "m", reg, sampleEvent); err != nil {
		t.Fatalf("RunIncident: %v", err)
	}
	if tool.calls.Load() != 0 {
		t.Fatalf("tool calls = %d, want 0", tool.calls.Load())
	}
}

func TestRunIncidentRunaway(t *testing.T) {
	client := mockLLM(t, []openai.ChatCompletionResponse{toolCallResp()}) // always tool calls
	reg, _ := regWithTool()

	_, err := RunIncident(context.Background(), client, "m", reg, sampleEvent)
	if err == nil || !strings.Contains(err.Error(), "max iterations") {
		t.Fatalf("expected max-iterations error, got %v", err)
	}
}
