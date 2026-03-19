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

// OllamaProvider is the local AI provider via Ollama.
// Zero cloud dependency, zero API key, works offline.
type OllamaProvider struct {
	endpoint string // "http://localhost:11434"
	model    string // "qwen2.5:7b", "llama3.1:8b"
	client   *http.Client
}

// NewOllamaProvider cree un provider Ollama.
func NewOllamaProvider(endpoint, model string, timeout time.Duration) *OllamaProvider {
	if endpoint == "" {
		endpoint = "http://localhost:11434"
	}
	if model == "" {
		model = "qwen2.5:7b"
	}
	return &OllamaProvider{
		endpoint: endpoint,
		model:    model,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (p *OllamaProvider) Name() string { return "ollama" }

// Available verifie si Ollama repond sur le endpoint configure.
func (p *OllamaProvider) Available() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", p.endpoint+"/api/tags", nil)
	if err != nil {
		return false
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// ollamaRequest est le format de requete Ollama /api/generate.
type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	System string `json:"system,omitempty"`
	Stream bool   `json:"stream"`
	Options struct {
		Temperature float64 `json:"temperature,omitempty"`
		NumPredict  int     `json:"num_predict,omitempty"`
	} `json:"options,omitempty"`
}

// ollamaResponse est le format de reponse Ollama /api/generate (stream=false).
type ollamaResponse struct {
	Model    string `json:"model"`
	Response string `json:"response"`
	Done     bool   `json:"done"`
	TotalDuration  int64 `json:"total_duration"`
	EvalCount      int   `json:"eval_count"`
}

// Query envoie un prompt a Ollama et retourne la reponse.
func (p *OllamaProvider) Query(ctx context.Context, req Request) (Response, error) {
	start := time.Now()

	ollamaReq := ollamaRequest{
		Model:  p.model,
		Prompt: req.UserPrompt,
		System: req.SystemPrompt,
		Stream: false,
	}
	ollamaReq.Options.Temperature = req.Temperature
	if req.MaxTokens > 0 {
		ollamaReq.Options.NumPredict = req.MaxTokens
	}

	body, err := json.Marshal(ollamaReq)
	if err != nil {
		return Response{}, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.endpoint+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := p.client.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("ollama request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != 200 {
		respBody, _ := io.ReadAll(io.LimitReader(httpResp.Body, 1024))
		return Response{}, fmt.Errorf("ollama returned %d: %s", httpResp.StatusCode, string(respBody))
	}

	var ollamaResp ollamaResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&ollamaResp); err != nil {
		return Response{}, fmt.Errorf("failed to decode response: %w", err)
	}

	return Response{
		Content:    ollamaResp.Response,
		Provider:   "ollama",
		Model:      ollamaResp.Model,
		TokensUsed: ollamaResp.EvalCount,
		DurationMs: time.Since(start).Milliseconds(),
	}, nil
}
