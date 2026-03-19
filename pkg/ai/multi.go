package ai

import (
	"context"
	"fmt"
)

// ErrAllProvidersFailed is returned when all providers in the chain fail.
var ErrAllProvidersFailed = fmt.Errorf("all AI providers failed")

// MultiProvider is a fallback chain of AI providers.
// Tries each provider in order, stops at first one that responds.
type MultiProvider struct {
	providers []AIProvider
	// OnSkip is called when a provider is skipped (not available).
	OnSkip func(providerName string, reason string)
	// OnFail est appele quand un provider echoue.
	OnFail func(providerName string, err error)
	// OnSuccess est appele quand un provider repond.
	OnSuccess func(providerName string, model string)
}

// NewMultiProvider cree une fallback chain.
func NewMultiProvider(providers ...AIProvider) *MultiProvider {
	return &MultiProvider{providers: providers}
}

func (m *MultiProvider) Name() string { return "multi" }

func (m *MultiProvider) Available() bool {
	for _, p := range m.providers {
		if p.Available() {
			return true
		}
	}
	return false
}

func (m *MultiProvider) Query(ctx context.Context, req Request) (Response, error) {
	for _, p := range m.providers {
		if !p.Available() {
			if m.OnSkip != nil {
				m.OnSkip(p.Name(), "not available")
			}
			continue
		}
		resp, err := p.Query(ctx, req)
		if err == nil {
			if m.OnSuccess != nil {
				m.OnSuccess(p.Name(), resp.Model)
			}
			return resp, nil
		}
		if m.OnFail != nil {
			m.OnFail(p.Name(), err)
		}
	}
	return Response{}, ErrAllProvidersFailed
}
