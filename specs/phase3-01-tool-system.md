# Spec 3-01 — Tool System

## Title
Agent tool interface, OpenAI adapter, and registry.

## Description
The foundation of the agent. Defines a uniform `Tool` contract every capability
implements, an adapter that turns a `Tool` into the `openai.Tool` shape the LLM
expects, and a `Registry` that holds tools by name and dispatches calls. Keeps the
agent loop (spec 03) decoupled from any concrete tool.

## Instructions
- File: `internal/agent/tools.go` (≤150 LOC).
- Define the interface:
  ```go
  type Tool interface {
      Name() string
      Description() string
      Schema() json.RawMessage // JSON Schema for the arguments object
      Execute(ctx context.Context, input json.RawMessage) (string, error)
  }
  ```
- `func ToOpenAITool(t Tool) openai.Tool` — builds `openai.Tool{Type: "function",
  Function: &openai.FunctionDefinition{Name, Description, Parameters: t.Schema()}}`.
- `type Registry struct` wrapping `map[string]Tool` (guard with `sync.RWMutex`
  since tools may be registered at startup and read concurrently).
  - `New() *Registry`
  - `Register(t Tool)` — keyed by `t.Name()`.
  - `All() []Tool` — stable order for deterministic prompts (sort by name).
  - `OpenAITools() []openai.Tool` — `All()` mapped through `ToOpenAITool`.
  - `Dispatch(ctx, name string, input json.RawMessage) (string, error)` — returns
    a clear error string if the tool is unknown; logs name + input len + output
    len via `slog`.
- No package-level globals; the registry is constructed and injected.

## Validation test
`internal/agent/tools_test.go`:
1. Register a fake tool, `All()` returns it; `OpenAITools()[0].Function.Name`
   matches.
2. `Dispatch` on a known tool returns its output; on an unknown name returns a
   non-nil error mentioning the name.
3. `Dispatch` is race-clean: run 50 concurrent dispatches under `-race`.

## Acceptance criteria
- [ ] `internal/agent/tools.go` ≤150 LOC, compiles, `go vet` clean.
- [ ] `Tool`, `ToOpenAITool`, `Registry` exported as specified.
- [ ] `go test -race ./internal/agent/` passes for the tests above.
- [ ] No API keys, no network calls in this file.
