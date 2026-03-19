// LiaSecProvider calls the LIA-SEC platform's UniversalAIManager via HTTP.
// Used in API mode (--serve) when LiaProbe is integrated into LIA-SEC.
// The LIA-SEC backend handles provider selection, fallback chain, and rate limiting.
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

// LiaSecProvider delegates AI calls to the LIA-SEC backend.
type LiaSecProvider struct {
	endpoint string // "http://localhost:8081/api/ai"
	apiKey   string // JWT or internal API key
	client   *http.Client
}

// NewLiaSecProvider creates a LIA-SEC AI provider.
func NewLiaSecProvider(endpoint, apiKey string, timeout time.Duration) *LiaSecProvider {
	if endpoint == "" {
		endpoint = "http://localhost:8081/api/ai"
	}
	return &LiaSecProvider{
		endpoint: endpoint,
		apiKey:   apiKey,
		client:   &http.Client{Timeout: timeout},
	}
}

func (p *LiaSecProvider) Name() string { return "liasec" }

// Available checks if the LIA-SEC AI endpoint responds.
func (p *LiaSecProvider) Available() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", p.endpoint+"/health", nil)
	if err != nil {
		return false
	}
	if p.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// liaSecRequest is the request format for LIA-SEC AI API.
type liaSecRequest struct {
	Prompt      string  `json:"prompt"`
	System      string  `json:"system,omitempty"`
	MaxTokens   int     `json:"max_tokens,omitempty"`
	Temperature float64 `json:"temperature,omitempty"`
	Source      string  `json:"source"` // "liaprobe"
}

// liaSecResponse is the response format from LIA-SEC AI API.
type liaSecResponse struct {
	Content    string `json:"content"`
	Provider   string `json:"provider"`
	Model      string `json:"model"`
	TokensUsed int    `json:"tokens_used"`
	DurationMs int64  `json:"duration_ms"`
}

// Query sends a prompt to the LIA-SEC AI backend.
func (p *LiaSecProvider) Query(ctx context.Context, req Request) (Response, error) {
	start := time.Now()

	// Build prompt from context + user prompt
	prompt := req.UserPrompt
	if len(req.Context) > 0 {
		for _, m := range req.Context {
			prompt = m.Role + ": " + m.Content + "\n" + prompt
		}
	}

	lsReq := liaSecRequest{
		Prompt:      prompt,
		System:      req.SystemPrompt,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		Source:      "liaprobe",
	}

	body, err := json.Marshal(lsReq)
	if err != nil {
		return Response{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.endpoint+"/query", bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	}

	httpResp, err := p.client.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("liasec request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != 200 {
		respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1024))
		return Response{}, fmt.Errorf("liasec returned %d: %s", httpResp.StatusCode, string(respBody))
	}

	var lsResp liaSecResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&lsResp); err != nil {
		return Response{}, fmt.Errorf("failed to decode response: %w", err)
	}

	return Response{
		Content:    lsResp.Content,
		Provider:   "liasec/" + lsResp.Provider,
		Model:      lsResp.Model,
		TokensUsed: lsResp.TokensUsed,
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}
