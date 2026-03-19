// Package output formats scan results for display.
// Implementations: JSON (default), table (human CLI).
package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/mo0ogly/liaprobe/pkg/scanner"
)

// JSONWriter writes results in JSON to a writer.
type JSONWriter struct {
	w      io.Writer
	pretty bool
}

// NewJSONWriter cree un writer JSON.
func NewJSONWriter(w io.Writer, pretty bool) *JSONWriter {
	return &JSONWriter{w: w, pretty: pretty}
}

// WriteScanResult ecrit un resultat de scan en JSON.
func (jw *JSONWriter) WriteScanResult(result *scanner.ScanResult) error {
	var data []byte
	var err error

	if jw.pretty {
		data, err = json.MarshalIndent(result, "", "  ")
	} else {
		data, err = json.Marshal(result)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	data = append(data, '\n')
	_, err = jw.w.Write(data)
	return err
}

// WriteHostResult ecrit un resultat de host en JSON (streaming).
func (jw *JSONWriter) WriteHostResult(host *scanner.HostResult) error {
	var data []byte
	var err error

	if jw.pretty {
		data, err = json.MarshalIndent(host, "", "  ")
	} else {
		data, err = json.Marshal(host)
	}
	if err != nil {
		return fmt.Errorf("failed to marshal host result: %w", err)
	}

	data = append(data, '\n')
	_, err = jw.w.Write(data)
	return err
}
