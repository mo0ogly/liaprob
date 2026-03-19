// Package ai defines the abstract interface for LiaProbe AI providers.
// Implementations: Ollama (standalone), LIA-SEC (API), OpenAI-compatible, Noop.
package ai

import "context"

// AIProvider is the abstract interface for any AI backend.
// Each implementation must be autonomous and thread-safe.
type AIProvider interface {
	// Name returns the provider name (for journal).
	Name() string

	// Available returns true if the provider is operational.
	Available() bool

	// Query sends a prompt and receives a response.
	Query(ctx context.Context, req Request) (Response, error)
}

// Request is a request to the AI provider.
type Request struct {
	SystemPrompt string    `json:"system_prompt"`
	UserPrompt   string    `json:"user_prompt"`
	MaxTokens    int       `json:"max_tokens"`
	Temperature  float64   `json:"temperature"`
	Context      []Message `json:"context,omitempty"` // Historique (memoire de travail)
}

// Message est un message dans l'historique de conversation.
type Message struct {
	Role    string `json:"role"`    // "user", "assistant", "system"
	Content string `json:"content"`
}

// Response est la reponse du provider IA.
type Response struct {
	Content    string `json:"content"`
	Provider   string `json:"provider"`
	Model      string `json:"model"`
	TokensUsed int    `json:"tokens_used"`
	DurationMs int64  `json:"duration_ms"`
}
