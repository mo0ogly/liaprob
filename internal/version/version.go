// Package version contains version information for LiaProbe.
// Values are injected at build time via ldflags.
package version

var (
	// Version is the semantic version (injected at build).
	Version = "0.2.0"

	// Commit is the short git hash (injected at build).
	Commit = "unknown"

	// BuildDate is the ISO 8601 build date (injected at build).
	BuildDate = "unknown"
)
