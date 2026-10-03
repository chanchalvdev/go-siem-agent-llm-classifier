package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	openai "github.com/sashabaranov/go-openai"
)

// streamMockLLM answers non-streaming calls with a tool_call then a stop, and
// answers the streaming synthesis call with SSE chunks.
func streamMockLLM(t *testing.T) *openai.Client {
	t.Helper()
	var nonStream atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"stream":true`) {
			writeSSE(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if nonStream.Add(1) == 1 {
			_ = json.NewEncoder(w).Encode(toolCallResp())
		} else {
			_ = json.NewEncoder(w).Encode(stopResp(""))
		}
	}))
	t.Cleanup(srv.Close)
	cfg := openai.DefaultConfig("test")
	cfg.BaseURL = srv.URL
	return openai.NewClientWithConfig(cfg)
}

func writeSSE(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	flush, _ := w.(http.Flusher)
	for _, tok := range []string{"## Sum", "mary\n", "done"} {
		chunk := openai.ChatCompletionStreamResponse{Choices: []openai.ChatCompletionStreamChoice{{
			Delta: openai.ChatCompletionStreamChoiceDelta{Content: tok},
		}}}
		b, _ := json.Marshal(chunk)
		_, _ = w.Write([]byte("data: " + string(b) + "\n\n"))
		if flush != nil {
			flush.Flush()
		}
	}
	_, _ = w.Write([]byte("data: [DONE]\n\n"))
}

func TestRunIncidentStreamEmitsEvents(t *testing.T) {
	client := streamMockLLM(t)
	reg, tool := regWithTool()

	var types []string
	var playbook strings.Builder
	err := RunIncidentStream(context.Background(), client, "m", reg, sampleEvent,
		func(e AgentEvent) {
			types = append(types, e.Type)
			if e.Type == "chunk" {
				playbook.WriteString(e.Data)
			}
		})
	if err != nil {
		t.Fatalf("RunIncidentStream: %v", err)
	}
	if tool.calls.Load() != 1 {
		t.Fatalf("tool calls = %d, want 1", tool.calls.Load())
	}
	for _, want := range []string{"tool_call", "tool_result", "chunk", "done"} {
		if !contains(types, want) {
			t.Errorf("missing %q event in %v", want, types)
		}
	}
	if got := playbook.String(); got != "## Summary\ndone" {
		t.Errorf("assembled playbook = %q", got)
	}
	if types[len(types)-1] != "done" {
		t.Errorf("last event = %q, want done", types[len(types)-1])
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestRunBriefStreamUsesGivenPrompt(t *testing.T) {
	var sawPrompt atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "CUSTOM-SYSTEM") && strings.Contains(string(body), "BRIEF-123") {
			sawPrompt.Store(true)
		}
		if strings.Contains(string(body), `"stream":true`) {
			writeSSE(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(stopResp(""))
	}))
	defer srv.Close()
	cfg := openai.DefaultConfig("test")
	cfg.BaseURL = srv.URL
	reg, _ := regWithTool()

	var out strings.Builder
	err := RunBriefStream(context.Background(), openai.NewClientWithConfig(cfg), "m", reg, "CUSTOM-SYSTEM", "BRIEF-123",
		func(e AgentEvent) {
			if e.Type == "chunk" {
				out.WriteString(e.Data)
			}
		})
	if err != nil || !sawPrompt.Load() || out.String() != "## Summary\ndone" {
		t.Fatalf("err=%v sawPrompt=%v out=%q", err, sawPrompt.Load(), out.String())
	}
}
