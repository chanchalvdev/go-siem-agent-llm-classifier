package agent

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// fakeTool is a minimal Tool for registry tests.
type fakeTool struct {
	name string
	out  string
}

func (f fakeTool) Name() string            { return f.name }
func (f fakeTool) Description() string     { return "fake " + f.name }
func (f fakeTool) Schema() json.RawMessage { return json.RawMessage(`{"type":"object"}`) }
func (f fakeTool) Execute(context.Context, json.RawMessage) (string, error) {
	return f.out, nil
}

func TestRegistryRegisterAndAdapt(t *testing.T) {
	r := New()
	r.Register(fakeTool{name: "check_abuseipdb", out: "ok"})
	if got := len(r.All()); got != 1 {
		t.Fatalf("All() len = %d, want 1", got)
	}
	tools := r.OpenAITools()
	if tools[0].Function.Name != "check_abuseipdb" {
		t.Fatalf("adapted name = %q", tools[0].Function.Name)
	}
}

func TestRegistryDispatch(t *testing.T) {
	r := New()
	r.Register(fakeTool{name: "t1", out: "result-1"})

	got, err := r.Dispatch(context.Background(), "t1", json.RawMessage(`{}`))
	if err != nil || got != "result-1" {
		t.Fatalf("Dispatch known = (%q, %v)", got, err)
	}

	_, err = r.Dispatch(context.Background(), "missing", json.RawMessage(`{}`))
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("Dispatch unknown err = %v, want mention of name", err)
	}
}

func TestRegistryConcurrentDispatch(t *testing.T) {
	r := New()
	r.Register(fakeTool{name: "t1", out: "x"})
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.Dispatch(context.Background(), "t1", json.RawMessage(`{}`))
		}()
	}
	wg.Wait()
}
