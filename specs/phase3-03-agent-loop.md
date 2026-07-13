# Spec 3-03 — Agent Loop

## Title
Autonomous tool-use loop that produces an incident playbook.

## Description
The brain of Phase 3. Given a classified event, it drives an OpenAI-compatible
chat loop: the LLM decides which tools to call, the loop dispatches them through
the registry, feeds results back, and repeats until the model emits a final
playbook. Bounded iterations prevent runaway loops.

## Instructions
- File: `internal/agent/agent.go` (≤150 LOC).
- Signature:
  ```go
  func RunIncident(ctx context.Context, client *openai.Client, model string,
      reg *Registry, ev models.ClassifiedEvent) (string, error)
  ```
- Steps:
  1. System prompt: role = senior security incident responder; instruct it to use
     tools to enrich, then output a concise Markdown playbook (Summary, Evidence,
     Threat Intel, Recommended Actions).
  2. User message: marshal the key `ClassifiedEvent` fields (attack type, MITRE,
     severity, IOCs, summary, raw log) as JSON.
  3. Loop, max **8** iterations:
     - `client.CreateChatCompletion` with `Tools: reg.OpenAITools()`.
     - Append the assistant message to history.
     - If `FinishReason == ToolCalls`: for each call, `reg.Dispatch`, append a
       `ChatMessageRoleTool` message with `ToolCallID` set; continue.
     - Else return the assistant `Content` as the playbook.
  4. Exhausting 8 iterations → error `"agent exceeded max iterations"`.
- Log each tool call (name, output length) with `slog`.
- Keep transport/streaming out of this file (that's spec 04).

## Validation test
`internal/agent/agent_test.go` — mock the LLM with `httptest.NewServer` returning
canned chat-completion JSON, point `openai.Client` at it:
1. **One tool then stop:** first response = one tool call; second = `stop`. Assert
   the mock tool ran exactly once and the final text is returned.
2. **Immediate stop:** first response = `stop`, no tools. Assert zero tool calls.
3. **Runaway:** LLM always returns tool calls. Assert loop stops at 8 and errors.

## Acceptance criteria
- [ ] `agent.go` ≤150 LOC, `go vet` clean.
- [ ] Iteration cap enforced at 8, returns an error (no infinite loop).
- [ ] Tool results fed back with correct `ToolCallID`.
- [ ] All three scenarios pass under `go test -race`.
- [ ] Reuses `models` and the classifier's `openai.Client`; no new LLM client type.
