// Package ai - Anthropic Claude provider for LiaProbe.
// Uses the Anthropic Messages API (not OpenAI-compatible).
// Supports Claude Opus, Sonnet, Haiku via api.anthropic.com.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AnthropicProvider connects to the Anthropic Messages API.
type AnthropicProvider struct {
	endpoint string
	model    string
	apiKey   string
	client   *http.Client
}

// NewAnthropicProvider creates a Claude provider.
func NewAnthropicProvider(endpoint, model, apiKey string, timeout time.Duration) *AnthropicProvider {
	if endpoint == "" {
		endpoint = "https://api.anthropic.com"
	}
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}
	return &AnthropicProvider{
		endpoint: endpoint,
		model:    model,
		apiKey:   apiKey,
		client:   &http.Client{Timeout: timeout},
	}
}

func (p *AnthropicProvider) Name() string { return "anthropic" }

func (p *AnthropicProvider) Available() bool {
	return p.apiKey != ""
}

// Anthropic Messages API request/response types.
type anthropicRequest struct {
	Model     string              `json:"model"`
	MaxTokens int                 `json:"max_tokens"`
	System    string              `json:"system,omitempty"`
	Messages  []anthropicMessage  `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	ID    string `json:"id"`
	Model string `json:"model"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Usage struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (p *AnthropicProvider) Query(ctx context.Context, req Request) (Response, error) {
	start := time.Now()

	var messages []anthropicMessage
	for _, m := range req.Context {
		messages = append(messages, anthropicMessage{Role: m.Role, Content: m.Content})
	}
	messages = append(messages, anthropicMessage{Role: "user", Content: req.UserPrompt})

	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 1024
	}

	aReq := anthropicRequest{
		Model:     p.model,
		MaxTokens: maxTokens,
		System:    req.SystemPrompt,
		Messages:  messages,
	}

	body, err := json.Marshal(aReq)
	if err != nil {
		return Response{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := p.endpoint + "/v1/messages"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	httpResp, err := p.client.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("anthropic request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != 200 {
		respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1024))
		return Response{}, fmt.Errorf("anthropic returned %d: %s", httpResp.StatusCode, string(respBody))
	}

	var aResp anthropicResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&aResp); err != nil {
		return Response{}, fmt.Errorf("failed to decode response: %w", err)
	}

	if aResp.Error != nil {
		return Response{}, fmt.Errorf("anthropic error: %s: %s", aResp.Error.Type, aResp.Error.Message)
	}

	content := ""
	for _, block := range aResp.Content {
		if block.Type == "text" {
			content += block.Text
		}
	}

	return Response{
		Content:    content,
		Provider:   "anthropic",
		Model:      aResp.Model,
		TokensUsed: aResp.Usage.InputTokens + aResp.Usage.OutputTokens,
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}
