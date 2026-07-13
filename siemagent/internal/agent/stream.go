package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	openai "github.com/sashabaranov/go-openai"

	"github.com/chverma/siemagent/internal/models"
)

// AgentEvent is a single update emitted during a streaming investigation.
// Type is one of: tool_call, tool_result, chunk, done, error.
type AgentEvent struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

// RunIncidentStream runs the tool-enrichment loop, emitting an AgentEvent for
// each tool call/result, then streams the final playbook token by token.
func RunIncidentStream(ctx context.Context, client *openai.Client, model string,
	reg *Registry, ev models.ClassifiedEvent, send func(AgentEvent)) error {

	messages, err := seedMessages(ev)
	if err != nil {
		send(AgentEvent{Type: "error", Data: err.Error()})
		return err
	}
	tools := reg.OpenAITools()

	// Enrichment: let the model call tools until it stops requesting them.
	for i := 0; i < maxIterations; i++ {
		resp, err := client.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
			Model: model, Messages: messages, Tools: tools,
		})
		if err != nil {
			send(AgentEvent{Type: "error", Data: err.Error()})
			return fmt.Errorf("agent stream: %w", err)
		}
		if len(resp.Choices) == 0 {
			return failStream(send, errors.New("empty completion"))
		}
		if resp.Choices[0].FinishReason != openai.FinishReasonToolCalls {
			break
		}
		messages = append(messages, resp.Choices[0].Message)
		messages = append(messages, dispatchStream(ctx, reg, resp.Choices[0].Message.ToolCalls, send)...)
	}
	return synthesize(ctx, client, model, messages, send)
}

// dispatchStream runs each tool call, emitting tool_call/tool_result events, and
// returns the tool-role messages to append to the conversation.
func dispatchStream(ctx context.Context, reg *Registry, calls []openai.ToolCall,
	send func(AgentEvent)) []openai.ChatCompletionMessage {

	out := make([]openai.ChatCompletionMessage, 0, len(calls))
	for _, call := range calls {
		meta, _ := json.Marshal(map[string]string{"name": call.Function.Name, "input": call.Function.Arguments})
		send(AgentEvent{Type: "tool_call", Data: string(meta)})

		result, err := reg.Dispatch(ctx, call.Function.Name, json.RawMessage(call.Function.Arguments))
		if err != nil {
			result = fmt.Sprintf(`{"error":%q}`, err.Error())
		}
		send(AgentEvent{Type: "tool_result", Data: result})
		out = append(out, openai.ChatCompletionMessage{
			Role: openai.ChatMessageRoleTool, Content: result, ToolCallID: call.ID,
		})
	}
	return out
}

// synthesize streams the final playbook (no tools) and emits chunk + done.
func synthesize(ctx context.Context, client *openai.Client, model string,
	messages []openai.ChatCompletionMessage, send func(AgentEvent)) error {

	// Without an explicit instruction, tool-trained models seeing the tool
	// history may emit raw tool-call markup as text since no tools are declared.
	messages = append(messages, openai.ChatCompletionMessage{
		Role: openai.ChatMessageRoleUser,
		Content: "Using the intelligence gathered above, write the final incident " +
			"response playbook in markdown. Do not call any tools — respond with prose only.",
	})
	stream, err := client.CreateChatCompletionStream(ctx, openai.ChatCompletionRequest{
		Model: model, Messages: messages,
	})
	if err != nil {
		return failStream(send, err)
	}
	defer stream.Close()

	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return failStream(send, err)
		}
		if len(resp.Choices) > 0 {
			if chunk := resp.Choices[0].Delta.Content; chunk != "" {
				send(AgentEvent{Type: "chunk", Data: chunk})
			}
		}
	}
	send(AgentEvent{Type: "done", Data: ""})
	return nil
}

func failStream(send func(AgentEvent), err error) error {
	send(AgentEvent{Type: "error", Data: err.Error()})
	return fmt.Errorf("agent stream: %w", err)
}
