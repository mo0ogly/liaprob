package config

import "time"

// Default values for the scanner -- validated in LIA-SEC lab.
const (
	DefaultPortConnectTimeout  = 500 * time.Millisecond
	DefaultAliveConnectTimeout = 300 * time.Millisecond
	DefaultSubdomainTimeout    = 8 * time.Second
	DefaultPortWorkers         = 200
	DefaultAliveWorkers        = 50
	DefaultTargetWorkers       = 20
	DefaultMaxSubdomains       = 500
	DefaultMaxReplans          = 5
	DefaultAPIPort             = 8082

	// Fingerprint
	DefaultHTTPTimeoutMs       = 5000
	DefaultTCPTimeoutMs        = 3000
	DefaultTLSTimeoutMs        = 5000
	DefaultSSDPTimeoutMs       = 3000
	DefaultMaxProbesPerService = 10
	DefaultMaxBodySize         = 65536 // 64KB
	DefaultMaxBannerSize       = 4096
	DefaultConfidenceThreshold = 0.50
	DefaultFPParallelism       = 5

	// AI
	DefaultAITimeout    = 120 * time.Second
	DefaultAITemp       = 0.1
	DefaultAIMaxTokens  = 512
)

// Default retourne la configuration par defaut de LiaProbe.
func Default() *Config {
	return &Config{
		Mode:    ModeSmart,
		Profile: ProfileStandard,

		PortWorkers:         DefaultPortWorkers,
		AliveWorkers:        DefaultAliveWorkers,
		TargetWorkers:       DefaultTargetWorkers,
		MaxSubdomains:       DefaultMaxSubdomains,
		PortConnectTimeout:  DefaultPortConnectTimeout,
		AliveConnectTimeout: DefaultAliveConnectTimeout,
		SubdomainTimeout:    DefaultSubdomainTimeout,

		Fingerprint: FingerprintConfig{
			PatternDirs: []PatternDirConfig{
				{Path: "patterns/lia", Source: "lia", Priority: 100, Enabled: true},
			},
			HTTPTimeoutMs:       DefaultHTTPTimeoutMs,
			TCPTimeoutMs:        DefaultTCPTimeoutMs,
			TLSTimeoutMs:        DefaultTLSTimeoutMs,
			SSDPTimeoutMs:       DefaultSSDPTimeoutMs,
			MaxProbesPerService: DefaultMaxProbesPerService,
			MaxBodySize:         DefaultMaxBodySize,
			MaxBannerSize:       DefaultMaxBannerSize,
			ConfidenceThreshold: DefaultConfidenceThreshold,
			ProbesEnabled:       true,
			Parallelism:         DefaultFPParallelism,
		},

		AI: AIConfig{
			Enabled:  false,
			Provider: "noop",
			Timeout:  DefaultAITimeout,
			Temp:     DefaultAITemp,
			MaxTok:   DefaultAIMaxTokens,
		},

		OutputFormat: "json",
		Stream:       false,

		Store: StoreConfig{
			Type: "file",
		},

		Journal:    true, // Le journal est TOUJOURS actif
		DryRun:     false,
		MaxReplans: DefaultMaxReplans,
		APIPort:    DefaultAPIPort,
		Insecure:   false,
	}
}
