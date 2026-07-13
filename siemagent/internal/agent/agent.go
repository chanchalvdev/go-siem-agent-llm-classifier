package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	openai "github.com/sashabaranov/go-openai"

	"github.com/chverma/siemagent/internal/models"
)

// maxIterations caps the tool-use loop so a misbehaving LLM cannot run forever.
const maxIterations = 8

const incidentSystemPrompt = `You are a senior security incident responder.
You are given a classified security event. Use the available tools to enrich it
with external threat intelligence and historical context, then write a concise
incident playbook in Markdown with these sections:
## Summary
## Evidence
## Threat Intel
## Recommended Actions
Call tools only when they add value. When you have enough information, stop
calling tools and output the playbook.`

// seedMessages builds the system + user messages that open an investigation.
// Shared by the blocking and streaming loops (DRY).
func seedMessages(ev models.ClassifiedEvent) ([]openai.ChatCompletionMessage, error) {
	userMsg, err := json.Marshal(map[string]any{
		"attack_type": ev.AttackType,
		"mitre":       ev.MITRE,
		"severity":    ev.Severity,
		"iocs":        ev.IOCs,
		"summary":     ev.Summary,
		"raw_log":     ev.Event.Raw,
	})
	if err != nil {
		return nil, fmt.Errorf("agent: marshal event: %w", err)
	}
	return []openai.ChatCompletionMessage{
		{Role: openai.ChatMessageRoleSystem, Content: incidentSystemPrompt},
		{Role: openai.ChatMessageRoleUser, Content: string(userMsg)},
	}, nil
}

// RunIncident drives the bounded tool-use loop and returns the final playbook.
func RunIncident(ctx context.Context, client *openai.Client, model string,
	reg *Registry, ev models.ClassifiedEvent) (string, error) {

	messages, err := seedMessages(ev)
	if err != nil {
		return "", err
	}
	tools := reg.OpenAITools()

	for i := 0; i < maxIterations; i++ {
		resp, err := client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
			Model:    model,
			Messages: messages,
			Tools:    tools,
		})
		if err != nil {
			return "", fmt.Errorf("agent: chat completion: %w", err)
		}
		if len(resp.Choices) == 0 {
			return "", errors.New("agent: empty completion")
		}

		msg := resp.Choices[0].Message
		messages = append(messages, msg)

		if resp.Choices[0].FinishReason != openai.FinishReasonToolCalls {
			return msg.Content, nil
		}
		messages = append(messages, runToolCalls(ctx, reg, msg.ToolCalls)...)
	}
	return "", errors.New("agent exceeded max iterations")
}

// runToolCalls dispatches every requested tool call and returns the tool-role
// reply messages to append to the conversation.
func runToolCalls(ctx context.Context, reg *Registry, calls []openai.ToolCall) []openai.ChatCompletionMessage {
	out := make([]openai.ChatCompletionMessage, 0, len(calls))
	for _, call := range calls {
		result, err := reg.Dispatch(ctx, call.Function.Name, json.RawMessage(call.Function.Arguments))
		if err != nil {
			result = fmt.Sprintf(`{"error":%q}`, err.Error())
		}
		slog.Info("agent tool result", "component", "agent",
			"tool", call.Function.Name, "output_bytes", len(result))
		out = append(out, openai.ChatCompletionMessage{
			Role:       openai.ChatMessageRoleTool,
			Content:    result,
			ToolCallID: call.ID,
		})
	}
	return out
}
