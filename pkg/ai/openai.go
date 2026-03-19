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

// OpenAIProvider is an OpenAI API-compatible provider.
// Works with OpenAI, Groq, Together, vLLM, LM Studio, etc.
type OpenAIProvider struct {
	name     string
	endpoint string // "https://api.openai.com/v1" ou compatible
	model    string
	apiKey   string
	client   *http.Client
}

// NewOpenAIProvider cree un provider OpenAI-compatible.
func NewOpenAIProvider(name, endpoint, model, apiKey string, timeout time.Duration) *OpenAIProvider {
	if name == "" {
		name = "openai"
	}
	return &OpenAIProvider{
		name:     name,
		endpoint: endpoint,
		model:    model,
		apiKey:   apiKey,
		client:   &http.Client{Timeout: timeout},
	}
}

func (p *OpenAIProvider) Name() string { return p.name }

func (p *OpenAIProvider) Available() bool {
	return p.endpoint != "" && p.apiKey != ""
}

type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Temperature float64         `json:"temperature,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Model string `json:"model"`
	Usage struct {
		TotalTokens int `json:"total_tokens"`
	} `json:"usage"`
}

func (p *OpenAIProvider) Query(ctx context.Context, req Request) (Response, error) {
	start := time.Now()

	var messages []openAIMessage
	if req.SystemPrompt != "" {
		messages = append(messages, openAIMessage{Role: "system", Content: req.SystemPrompt})
	}
	for _, m := range req.Context {
		messages = append(messages, openAIMessage{Role: m.Role, Content: m.Content})
	}
	messages = append(messages, openAIMessage{Role: "user", Content: req.UserPrompt})

	oaiReq := openAIRequest{
		Model:       p.model,
		Messages:    messages,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
	}

	body, err := json.Marshal(oaiReq)
	if err != nil {
		return Response{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	url := p.endpoint + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	httpResp, err := p.client.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != 200 {
		respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1024))
		return Response{}, fmt.Errorf("API returned %d: %s", httpResp.StatusCode, string(respBody))
	}

	var oaiResp openAIResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&oaiResp); err != nil {
		return Response{}, fmt.Errorf("failed to decode response: %w", err)
	}

	if len(oaiResp.Choices) == 0 {
		return Response{}, fmt.Errorf("no choices in response")
	}

	return Response{
		Content:    oaiResp.Choices[0].Message.Content,
		Provider:   p.name,
		Model:      oaiResp.Model,
		TokensUsed: oaiResp.Usage.TotalTokens,
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}
