package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Ports tested for "host alive" check before full scan.
// A host is "up" if at least one of these ports responds (TCP connect or connection refused).
// Connection refused means the host's TCP stack is alive (RST received).
var AliveCheckPorts = []int{
	80, 443, 22, 445, 139, 135, 3389, 8080, 8443, 21, 23, 53,
	3306, 5432, 6379, 27017, 9200, 5672, 3000, 9090, 8500, 9000, 5601, 15672,
}

// AliveChecker determines which hosts are alive via fast TCP connect.
type AliveChecker struct {
	ConnectTimeout time.Duration
	Workers        int
}

// NewAliveChecker cree un alive checker.
func NewAliveChecker(connectTimeout time.Duration, workers int) *AliveChecker {
	return &AliveChecker{
		ConnectTimeout: connectTimeout,
		Workers:        workers,
	}
}

// CheckAlive filtre les targets et retourne uniquement ceux qui repondent.
// Pour les petits scopes (<= 4 IPs), retourne tous les targets sans filtrage.
func (ac *AliveChecker) CheckAlive(ctx context.Context, targets []Target) []Target {
	if len(targets) <= 4 {
		return targets
	}

	var (
		alive []Target
		mu    sync.Mutex
		wg    sync.WaitGroup
	)

	tasks := make(chan Target, len(targets))

	for i := 0; i < ac.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range tasks {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if ac.isAlive(target.IP) {
					mu.Lock()
					alive = append(alive, target)
					mu.Unlock()
				}
			}
		}()
	}

	for _, t := range targets {
		select {
		case <-ctx.Done():
			break
		case tasks <- t:
		}
	}
	close(tasks)
	wg.Wait()

	return alive
}

// isAlive teste si au moins un port du host repond.
// A host is alive if we get a successful connect OR a "connection refused" (RST).
// Only a timeout or "no route to host" means the host is down.
func (ac *AliveChecker) isAlive(ip string) bool {
	for _, port := range AliveCheckPorts {
		addr := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", addr, ac.ConnectTimeout)
		if err == nil {
			conn.Close()
			return true
		}
		// "connection refused" means the host IS alive (TCP RST received)
		if opErr, ok := err.(*net.OpError); ok {
			if sysErr, ok := opErr.Err.(*net.OpError); ok {
				_ = sysErr // nested OpError
			}
			// Check for ECONNREFUSED -- host is up but port is closed
			if opErr.Err != nil {
				errStr := opErr.Err.Error()
				if contains(errStr, "connection refused") || contains(errStr, "refused") {
					return true
				}
			}
		}
	}
	return false
}

// contains checks if s contains substr (avoids importing strings in scanner).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
