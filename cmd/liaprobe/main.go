// LiaProbe - Intelligent agentic network scanner
//
// Usage:
//
//	liaprobe [flags] <targets...>
//	liaprobe --serve                 # API server mode (LIA-SEC)
//
// Examples:
//
//	liaprobe 192.168.1.0/24
//	liaprobe --mode smart --ai ollama 10.0.0.1 10.0.0.2
//	liaprobe --mode specific --ports 22,80,443 192.168.1.1
//	liaprobe --mode hunt --hunt-service jenkins 10.0.0.0/24
//	liaprobe --output table --no-ai 192.168.1.1
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mo0ogly/liaprob/api"
	"github.com/mo0ogly/liaprob/internal/version"
	"github.com/mo0ogly/liaprob/pkg/agent"
	"github.com/mo0ogly/liaprob/pkg/ai"
	"github.com/mo0ogly/liaprob/pkg/config"
	"github.com/mo0ogly/liaprob/pkg/fingerprint"
	"github.com/mo0ogly/liaprob/pkg/log"
	"github.com/mo0ogly/liaprob/pkg/output"
	"github.com/mo0ogly/liaprob/pkg/scanner"
	"github.com/mo0ogly/liaprob/pkg/store"
)

func main() {
	// --- CLI Flags ---
	var (
		flagConfig      = flag.String("config", "", "Config file path (default: liaprobe.yaml)")
		flagProfile     = flag.String("profile", "", "Scan profile: fast, standard, thorough, stealth")
		flagMode        = flag.String("mode", "", "Scan mode: smart, full, specific, hunt")
		flagPorts       = flag.String("ports", "", "Ports to scan (comma-separated, mode specific)")
		flagHuntService = flag.String("hunt-service", "", "Service to hunt (mode hunt)")
		flagHuntBanner  = flag.String("hunt-banner", "", "Banner pattern to hunt (mode hunt)")
		flagOutput      = flag.String("output", "", "Output format: json, table")
		flagOutputFile  = flag.String("o", "", "Output file (default: stdout)")
		flagNoAI        = flag.Bool("no-ai", false, "Disable AI provider")
		flagAIProvider  = flag.String("ai", "", "AI provider: ollama, openai, groq, anthropic, claude, custom")
		flagAIEndpoint  = flag.String("ai-endpoint", "", "AI provider endpoint URL")
		flagAIModel     = flag.String("ai-model", "", "AI model name")
		flagAIKey       = flag.String("ai-key", "", "AI API key")
		flagWorkers     = flag.Int("workers", 0, "Port scan workers (0=default)")
		flagTimeout     = flag.Int("timeout", 0, "Port connect timeout in ms (0=default)")
		flagStoreType   = flag.String("store", "file", "Store backend: file, memory")
		flagStoreDir    = flag.String("store-dir", ".liaprobe", "Store directory for file backend")
		flagServe       = flag.Bool("serve", false, "Start API server mode")
		flagAPIPort     = flag.Int("api-port", 0, "API server port (0=default)")
		flagInsecure    = flag.Bool("insecure", false, "Allow insecure TLS connections")
		flagVersion     = flag.Bool("version", false, "Print version and exit")
		flagDryRun      = flag.Bool("dry-run", false, "Plan without executing")
		flagPretty      = flag.Bool("pretty", true, "Pretty-print JSON output")
		flagVerbose     = flag.Bool("verbose", false, "Enable verbose/debug output")
	)

	flag.Usage = func() {
		log.Info("LiaProbe %s - Intelligent Agentic Network Scanner\n", version.Version)
		log.Info("Usage: liaprobe [flags] <targets...>\n")
		log.Info("Targets: IPv4, CIDR, hostname\n")
		log.Info("Flags:")
		flag.PrintDefaults()
	}

	flag.Parse()

	// --- Log level ---
	if *flagVerbose {
		log.SetLevel(log.LevelDebug)
	}

	// --- Version ---
	if *flagVersion {
		log.Out("liaprobe %s (commit %s, built %s)", version.Version, version.Commit, version.BuildDate)
		os.Exit(0)
	}

	// --- API Server mode ---
	if *flagServe {
		runAPIServer(*flagStoreType, *flagStoreDir, *flagNoAI, *flagAIProvider, *flagAIEndpoint, *flagAIModel, *flagAIKey)
		return
	}

	// --- Targets ---
	targets := flag.Args()
	if len(targets) == 0 {
		log.Error("at least one target is required")
		flag.Usage()
		os.Exit(1)
	}

	// --- Config: file -> env -> profile -> CLI flags ---
	cfg, err := config.LoadFromFile(*flagConfig)
	if err != nil {
		log.Fatal("Config error: %s", err)
	}
	config.LoadFromEnv(cfg)

	// Apply profile if specified
	if *flagProfile != "" {
		config.ApplyProfile(cfg, config.ScanProfile(*flagProfile))
	}

	// CLI flags override (only if explicitly set)
	cfg.Targets = targets
	if *flagMode != "" {
		cfg.Mode = config.ScanMode(*flagMode)
	}
	if *flagOutput != "" {
		cfg.OutputFormat = *flagOutput
	}
	if *flagWorkers > 0 {
		cfg.PortWorkers = *flagWorkers
	}
	if *flagTimeout > 0 {
		cfg.PortConnectTimeout = time.Duration(*flagTimeout) * time.Millisecond
	}
	if *flagAPIPort > 0 {
		cfg.APIPort = *flagAPIPort
	}
	cfg.Insecure = *flagInsecure
	cfg.DryRun = *flagDryRun
	cfg.Serve = *flagServe

	// Parse ports
	if *flagPorts != "" {
		for _, p := range strings.Split(*flagPorts, ",") {
			p = strings.TrimSpace(p)
			port, err := strconv.Atoi(p)
			if err != nil || port < 1 || port > 65535 {
				log.Fatal("Invalid port: %s", p)
			}
			cfg.Ports = append(cfg.Ports, port)
		}
	}

	// Hunt mode
	if *flagHuntService != "" {
		cfg.HuntService = *flagHuntService
	}
	if *flagHuntBanner != "" {
		cfg.HuntBanner = *flagHuntBanner
	}

	// Validate config
	if err := config.Validate(cfg); err != nil {
		log.Fatal("Config validation error: %s", err)
	}

	// AI config: --ai flag enables AI, --no-ai disables
	if *flagAIProvider != "" {
		cfg.AI.Enabled = true
		cfg.AI.Provider = *flagAIProvider
	}
	if *flagNoAI {
		cfg.AI.Enabled = false
	}

	// --- AI Provider ---
	var aiProvider ai.AIProvider
	if !cfg.AI.Enabled {
		aiProvider = &ai.NoopProvider{}
	} else {
		aiProvider = buildAIProvider(*flagAIProvider, *flagAIEndpoint, *flagAIModel, *flagAIKey, cfg.AI.Timeout)
	}

	// --- Store ---
	var dataStore store.Store
	switch *flagStoreType {
	case "file":
		fs, err := store.NewFileStore(*flagStoreDir)
		if err != nil {
			log.Fatal("Failed to create file store: %s", err)
		}
		dataStore = fs
	case "memory":
		dataStore = store.NewMemoryStore()
	default:
		log.Fatal("Unknown store type: %s", *flagStoreType)
	}
	defer dataStore.Close()

	// --- Output ---
	var outputFile *os.File
	if *flagOutputFile != "" {
		f, err := os.Create(*flagOutputFile)
		if err != nil {
			log.Fatal("Failed to create output file: %s", err)
		}
		defer f.Close()
		outputFile = f
	} else {
		outputFile = os.Stdout
	}

	// --- Journal ---
	journal := agent.NewJournal()
	if *flagStoreType == "file" {
		journalDir := *flagStoreDir + "/journals"
		os.MkdirAll(journalDir, 0755)
	}

	// --- Context with signal handling ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info("\nInterrupt received, stopping scan...")
		cancel()
	}()

	// --- Build toolkit ---
	tools := &agent.ToolKit{
		TCPScanner:   scanner.NewTCPScanner(cfg.PortConnectTimeout, cfg.PortWorkers),
		AliveChecker: scanner.NewAliveChecker(cfg.AliveConnectTimeout, cfg.AliveWorkers),
		AI:           aiProvider,
		Config:       cfg,
	}

	// Initialize fingerprint engine if patterns are available
	if cfg.Fingerprint.ProbesEnabled {
		loader := fingerprint.NewPatternLoader(cfg.Fingerprint)
		idx, err := loader.LoadAll()
		if err != nil {
			log.Warn("Fingerprint patterns not loaded: %s", err)
		} else {
			fingerprint.SetPatternIndex(idx)
			tools.Matcher = fingerprint.NewFingerprintMatcher()
			tools.ProbeExec = fingerprint.NewProbeExecutor(cfg.Fingerprint)
			log.Debug("Loaded %d fingerprint patterns", idx.Stats.TotalPatterns)
		}
	}

	// --- Run agentic scan ---
	scanAgent := agent.NewAgent(cfg, tools, journal)
	goal := agent.ScanGoal{
		Description: "Scan " + strings.Join(targets, ", ") + " in " + string(cfg.Mode) + " mode",
		Targets:     targets,
		Mode:        string(cfg.Mode),
		Ports:       cfg.Ports,
		Service:     cfg.HuntService,
		Banner:      cfg.HuntBanner,
	}

	runResult := scanAgent.Run(ctx, goal)

	// --- Save results ---
	if err := dataStore.SaveScanResult(runResult.ScanResult); err != nil {
		log.Warn("Failed to save scan result: %s", err)
	}
	if err := dataStore.SaveJournal(runResult.ScanResult.ID, journal.Entries()); err != nil {
		log.Warn("Failed to save journal: %s", err)
	}

	// --- Output ---
	switch cfg.OutputFormat {
	case "table":
		tw := output.NewTableWriter(outputFile)
		tw.WriteScanResult(runResult.ScanResult)
	default:
		jw := output.NewJSONWriter(outputFile, *flagPretty)
		jw.WriteScanResult(runResult.ScanResult)
	}
}

// buildAIProvider builds the AI provider from CLI flags.
// Auto-detects API keys from environment variables if not provided via --ai-key.
func buildAIProvider(provider, endpoint, model, apiKey string, timeout time.Duration) ai.AIProvider {
	// Auto-resolve API key from env if not provided
	if apiKey == "" {
		apiKey = resolveAPIKey(provider)
	}

	switch provider {
	case "ollama":
		return ai.NewOllamaProvider(endpoint, model, timeout)

	case "anthropic", "claude":
		if model == "" {
			model = "claude-sonnet-4-20250514"
		}
		return ai.NewAnthropicProvider(endpoint, model, apiKey, timeout)

	case "openai":
		if endpoint == "" {
			endpoint = "https://api.openai.com/v1"
		}
		if model == "" {
			model = "gpt-4o"
		}
		return ai.NewOpenAIProvider("openai", endpoint, model, apiKey, timeout)

	case "groq":
		if endpoint == "" {
			endpoint = "https://api.groq.com/openai/v1"
		}
		if model == "" {
			model = "llama-3.3-70b-versatile"
		}
		return ai.NewOpenAIProvider("groq", endpoint, model, apiKey, timeout)

	case "custom":
		return ai.NewOpenAIProvider("custom", endpoint, model, apiKey, timeout)

	default:
		// Try Ollama by default if an endpoint is provided
		if endpoint != "" {
			return ai.NewOllamaProvider(endpoint, model, timeout)
		}
		// Fallback: MultiProvider Ollama (default) -> Noop
		ollamaDefault := ai.NewOllamaProvider("", "", timeout)
		return ai.NewMultiProvider(ollamaDefault, &ai.NoopProvider{})
	}
}

// resolveAPIKey auto-detects API keys from environment variables.
func resolveAPIKey(provider string) string {
	switch provider {
	case "groq":
		return os.Getenv("GROQ_API_KEY")
	case "anthropic", "claude":
		return os.Getenv("ANTHROPIC_API_KEY")
	case "openai":
		return os.Getenv("OPENAI_API_KEY")
	default:
		return ""
	}
}

// runAPIServer starts LiaProbe in HTTP API server mode.
func runAPIServer(storeType, storeDir string, noAI bool, aiProvider, aiEndpoint, aiModel, aiKey string) {
	cfg := config.Default()
	cfg.Serve = true

	// AI provider
	var aiProv ai.AIProvider
	if noAI {
		aiProv = &ai.NoopProvider{}
	} else if aiProvider == "liasec" {
		aiProv = ai.NewLiaSecProvider(aiEndpoint, aiKey, cfg.AI.Timeout)
	} else {
		aiProv = buildAIProvider(aiProvider, aiEndpoint, aiModel, aiKey, cfg.AI.Timeout)
	}

	// Store
	var dataStore store.Store
	switch storeType {
	case "file":
		fs, err := store.NewFileStore(storeDir)
		if err != nil {
			log.Fatal("Failed to create file store: %s", err)
		}
		dataStore = fs
	default:
		dataStore = store.NewMemoryStore()
	}
	defer dataStore.Close()

	// Toolkit
	tools := &agent.ToolKit{
		TCPScanner:   scanner.NewTCPScanner(cfg.PortConnectTimeout, cfg.PortWorkers),
		AliveChecker: scanner.NewAliveChecker(cfg.AliveConnectTimeout, cfg.AliveWorkers),
		AI:           aiProv,
		Config:       cfg,
	}

	// Fingerprint engine
	if cfg.Fingerprint.ProbesEnabled {
		loader := fingerprint.NewPatternLoader(cfg.Fingerprint)
		idx, err := loader.LoadAll()
		if err == nil {
			fingerprint.SetPatternIndex(idx)
			tools.Matcher = fingerprint.NewFingerprintMatcher()
			tools.ProbeExec = fingerprint.NewProbeExecutor(cfg.Fingerprint)
		}
	}

	// Start server
	srv := api.NewServer(cfg, dataStore, tools)

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info("\nShutting down API server...")
		shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
		defer shutdownCancel()
		srv.Shutdown(shutdownCtx)
	}()

	log.Info("LiaProbe API server starting on port %d", cfg.APIPort)
	if err := srv.Start(); err != nil && err.Error() != "http: Server closed" {
		log.Fatal("Server error: %s", err)
	}
}
