// Package agent implements the Phase 3 autonomous incident-response agent:
// a bounded tool-use loop over an OpenAI-compatible LLM.
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	openai "github.com/sashabaranov/go-openai"
)

// Tool is a single capability the agent can invoke. Implementations live in
// internal/agent/tools and must be safe for concurrent Execute calls.
type Tool interface {
	Name() string
	Description() string
	// Schema is the JSON Schema for the tool's arguments object.
	Schema() json.RawMessage
	// Execute runs the tool and returns a compact string for the LLM to read.
	Execute(ctx context.Context, input json.RawMessage) (string, error)
}

// ToOpenAITool adapts a Tool into the shape the chat API expects.
func ToOpenAITool(t Tool) openai.Tool {
	return openai.Tool{
		Type: openai.ToolTypeFunction,
		Function: &openai.FunctionDefinition{
			Name:        t.Name(),
			Description: t.Description(),
			Parameters:  t.Schema(),
		},
	}
}

// Registry holds tools by name and dispatches calls to them.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{tools: make(map[string]Tool)}
}

// Register adds a tool, keyed by its Name. A later Register with the same name
// overwrites the earlier one.
func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name()] = t
}

// All returns the registered tools sorted by name for deterministic prompts.
func (r *Registry) All() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// OpenAITools returns All() adapted for the chat API.
func (r *Registry) OpenAITools() []openai.Tool {
	all := r.All()
	out := make([]openai.Tool, len(all))
	for i, t := range all {
		out[i] = ToOpenAITool(t)
	}
	return out
}

// Dispatch runs the named tool with the given input.
func (r *Registry) Dispatch(ctx context.Context, name string, input json.RawMessage) (string, error) {
	r.mu.RLock()
	t, ok := r.tools[name]
	r.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("unknown tool %q", name)
	}
	out, err := t.Execute(ctx, input)
	if err != nil {
		slog.Warn("tool failed", "component", "agent", "tool", name, "error", err)
		return "", err
	}
	slog.Info("tool called", "component", "agent", "tool", name,
		"input_bytes", len(input), "output_bytes", len(out))
	return out, nil
}
