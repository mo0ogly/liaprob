package ai

import (
	"context"
	"errors"
)

// ErrNoProvider is returned when no AI provider is available.
var ErrNoProvider = errors.New("no AI provider available")

// NoopProvider is an AI provider that does nothing.
// Used as last-resort fallback: deterministic mode, no AI.
type NoopProvider struct{}

func (p *NoopProvider) Name() string         { return "noop" }
func (p *NoopProvider) Available() bool      { return false }
func (p *NoopProvider) Query(_ context.Context, _ Request) (Response, error) {
	return Response{}, ErrNoProvider
}
