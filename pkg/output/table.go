package output

import (
	"io"
	"strconv"
	"strings"

	"github.com/mo0ogly/liaprobe/pkg/log"
	"github.com/mo0ogly/liaprobe/pkg/scanner"
)

// TableWriter writes results in human-readable table format.
type TableWriter struct {
	w io.Writer
}

// NewTableWriter creates a table writer.
func NewTableWriter(w io.Writer) *TableWriter {
	return &TableWriter{w: w}
}

// writef writes a formatted string to the underlying writer.
func (tw *TableWriter) writef(format string, args ...interface{}) {
	io.WriteString(tw.w, log.Sprintf(format, args...))
}

// WriteScanResult writes a scan result in table format.
func (tw *TableWriter) WriteScanResult(result *scanner.ScanResult) error {
	// Header
	tw.writef("\nLiaProbe Scan Results [%s]\n", result.ID)
	tw.writef("Started: %s  Completed: %s\n",
		result.StartedAt.Format("2006-01-02 15:04:05"),
		result.CompletedAt.Format("2006-01-02 15:04:05"))
	tw.writef("Duration: %dms  Hosts: %d alive  Ports: %d open  Technologies: %d\n",
		result.Stats.DurationMs,
		result.Stats.HostsAlive,
		result.Stats.PortsOpen,
		result.Stats.TechnologiesFound)
	if result.Stats.Replans > 0 {
		tw.writef("Replans: %d  AI Queries: %d\n",
			result.Stats.Replans, result.Stats.AIQueries)
	}
	tw.writef("%s\n\n", strings.Repeat("-", 80))

	for _, host := range result.Hosts {
		if err := tw.WriteHostResult(&host); err != nil {
			return err
		}
	}

	// AI Analysis
	if result.AIAnalysis != "" {
		tw.writef("%s\n", strings.Repeat("-", 80))
		tw.writef("AI ANALYSIS:\n%s\n", result.AIAnalysis)
	}

	return nil
}

// WriteHostResult writes a single host result in table format.
func (tw *TableWriter) WriteHostResult(host *scanner.HostResult) error {
	if !host.Alive {
		return nil
	}

	label := host.Target.IP
	if host.Target.Hostname != "" {
		label = host.Target.IP + " (" + host.Target.Hostname + ")"
	}

	tw.writef("HOST: %s  [%d ports open, %d services]\n",
		label, len(host.OpenPorts), len(host.Services))

	if len(host.OpenPorts) == 0 {
		tw.writef("  (no open ports)\n\n")
		return nil
	}

	// Build service lookup by port
	svcByPort := make(map[int]scanner.ServiceInfo)
	for _, svc := range host.Services {
		svcByPort[svc.Port] = svc
	}

	// Port table with service info
	tw.writef("  %-8s %-10s %-25s %-12s %s\n",
		"PORT", "PROTO", "SERVICE", "VERSION", "BANNER")
	tw.writef("  %-8s %-10s %-25s %-12s %s\n",
		"----", "-----", "-------", "-------", "------")

	for _, port := range host.OpenPorts {
		svcName := ""
		svcVersion := ""
		if svc, ok := svcByPort[port.Port]; ok {
			svcName = svc.Name
			svcVersion = svc.Version
			if svcVersion == "" && svc.CPE != "" {
				svcVersion = "(CPE)"
			}
		}

		banner := port.Banner
		if len(banner) > 40 {
			banner = banner[:37] + "..."
		}
		// Remove newlines from banner
		banner = strings.ReplaceAll(banner, "\n", " ")
		banner = strings.ReplaceAll(banner, "\r", "")

		tw.writef("  %-8d %-10s %-25s %-12s %s\n",
			port.Port, port.Protocol, truncStr(svcName, 25), truncStr(svcVersion, 12), banner)
	}

	// Service detail table if services found
	if len(host.Services) > 0 {
		tw.writef("\n  Technologies identified:\n")
		for _, svc := range host.Services {
			conf := strconv.Itoa(int(svc.Confidence*100)) + "%%"
			cpe := svc.CPE
			if cpe == "" {
				cpe = "-"
			}
			tw.writef("    [%s] %s %s  CPE: %s\n",
				conf, svc.Name, svc.Version, cpe)
		}
	}

	io.WriteString(tw.w, "\n")
	return nil
}

// truncStr truncates a string to max length.
func truncStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
