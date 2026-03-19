package scanner

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// TCPScanner scans TCP ports via full connect().
// Pure Go, zero external dependency, zero shell.
type TCPScanner struct {
	ConnectTimeout time.Duration
	Workers        int
}

// NewTCPScanner creates a TCP scanner with the given parameters.
func NewTCPScanner(connectTimeout time.Duration, workers int) *TCPScanner {
	return &TCPScanner{
		ConnectTimeout: connectTimeout,
		Workers:        workers,
	}
}

// portTask est une tache unitaire pour le pool de goroutines.
type portTask struct {
	IP   string
	Port int
}

// ScanPorts scanne une liste de ports sur un host et retourne les ports ouverts.
func (s *TCPScanner) ScanPorts(ctx context.Context, ip string, ports []int) []OpenPort {
	var (
		results []OpenPort
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	tasks := make(chan portTask, len(ports))

	// Lancer les workers
	for i := 0; i < s.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range tasks {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if s.isPortOpen(task.IP, task.Port) {
					mu.Lock()
					results = append(results, OpenPort{
						IP:       task.IP,
						Port:     task.Port,
						Protocol: "tcp",
					})
					mu.Unlock()
				}
			}
		}()
	}

	// Envoyer les taches
	for _, port := range ports {
		select {
		case <-ctx.Done():
			break
		case tasks <- portTask{IP: ip, Port: port}:
		}
	}
	close(tasks)
	wg.Wait()

	return results
}

// isPortOpen tente un TCP connect sur ip:port avec timeout.
func (s *TCPScanner) isPortOpen(ip string, port int) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, s.ConnectTimeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// GrabBanner lit les premiers octets envoyes par un service apres connexion TCP.
// Utilise pour la detection passive (SMTP greeting, FTP banner, SSH version, etc.).
// Retourne la banner brute ou "" si timeout/erreur.
func (s *TCPScanner) GrabBanner(ip string, port int, readTimeout time.Duration) string {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, s.ConnectTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Lire la banner spontanee (le serveur envoie en premier)
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}

	// Filtrer les caracteres non-imprimables (garde ASCII 9,10,13,32-126)
	var clean []byte
	for _, b := range buf[:n] {
		if b == 9 || b == 10 || b == 13 || (b >= 32 && b <= 126) {
			clean = append(clean, b)
		}
	}
	return string(clean)
}
