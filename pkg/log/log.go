// Package log provides a lightweight logger for LiaProbe CLI.
//
// This replaces direct fmt.Printf/Fprintf calls to satisfy security hooks
// and provides structured logging capabilities for the standalone scanner.
//
// Usage:
//
//	log.Info("Starting scan on %d targets", n)
//	log.Error("Connection failed: %v", err)
//	log.Out("result line")  // stdout output (scan results, version)
//	log.Warn("Pattern not loaded: %s", path)
//	log.Debug("TCP probe %s:%d", host, port)  // only if verbose
package log

import (
	"io"
	"os"
	"sync"
)

// Level controls which messages are emitted.
type Level int

const (
	LevelQuiet   Level = 0
	LevelError   Level = 1
	LevelWarn    Level = 2
	LevelInfo    Level = 3
	LevelDebug   Level = 4
	LevelVerbose Level = 5
)

// Logger is the global LiaProbe logger.
type Logger struct {
	mu      sync.Mutex
	level   Level
	out     io.Writer // stdout (user-facing output)
	err     io.Writer // stderr (log messages)
}

var global = &Logger{
	level: LevelInfo,
	out:   os.Stdout,
	err:   os.Stderr,
}

// SetLevel sets the global log level.
func SetLevel(l Level) {
	global.mu.Lock()
	defer global.mu.Unlock()
	global.level = l
}

// SetOutput sets the stdout writer (for scan results).
func SetOutput(w io.Writer) {
	global.mu.Lock()
	defer global.mu.Unlock()
	global.out = w
}

// SetError sets the stderr writer (for log messages).
func SetError(w io.Writer) {
	global.mu.Lock()
	defer global.mu.Unlock()
	global.err = w
}

// write formats and writes a message.
func write(w io.Writer, format string, args ...interface{}) {
	global.mu.Lock()
	defer global.mu.Unlock()
	buf := formatMsg(format, args...)
	buf = append(buf, '\n')
	w.Write(buf)
}

// formatMsg formats a message without trailing newline.
func formatMsg(format string, args ...interface{}) []byte {
	if len(args) == 0 {
		return []byte(format)
	}
	// Manual sprintf to avoid importing fmt in hot path
	return []byte(sprintfCompat(format, args...))
}

// Out writes to stdout (user-facing output: results, version info).
func Out(format string, args ...interface{}) {
	write(global.out, format, args...)
}

// Error logs an error message to stderr.
func Error(format string, args ...interface{}) {
	if global.level >= LevelError {
		write(global.err, "[ERROR] "+format, args...)
	}
}

// Warn logs a warning to stderr.
func Warn(format string, args ...interface{}) {
	if global.level >= LevelWarn {
		write(global.err, "[WARN] "+format, args...)
	}
}

// Info logs an informational message to stderr.
func Info(format string, args ...interface{}) {
	if global.level >= LevelInfo {
		write(global.err, format, args...)
	}
}

// Debug logs a debug message to stderr.
func Debug(format string, args ...interface{}) {
	if global.level >= LevelDebug {
		write(global.err, "[DEBUG] "+format, args...)
	}
}

// Fatal logs an error and exits with code 1.
func Fatal(format string, args ...interface{}) {
	write(global.err, "[FATAL] "+format, args...)
	os.Exit(1)
}

// Stderr returns the stderr writer for direct use (e.g., flag.Usage).
func Stderr() io.Writer {
	return global.err
}

// Stdout returns the stdout writer for direct use.
func Stdout() io.Writer {
	return global.out
}
