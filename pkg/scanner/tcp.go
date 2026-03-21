package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// mongoIsMasterMsg builds a minimal MongoDB wire protocol isMaster command.
func mongoIsMasterMsg() []byte {
	// OP_QUERY for isMaster on admin.$cmd
	doc := []byte{
		// BSON: {"isMaster": 1}
		0x13, 0x00, 0x00, 0x00, // doc size (19 bytes)
		0x10,                                     // type: int32
		'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0x00, // key: "isMaster\0"
		0x01, 0x00, 0x00, 0x00, // value: 1
		0x00, // doc terminator
	}
	ns := []byte("admin.$cmd\x00")

	// Header: msgLength(4) + requestID(4) + responseTo(4) + opCode(4)
	// OP_QUERY: flags(4) + ns + numberToSkip(4) + numberToReturn(4) + doc
	headerLen := 16
	bodyLen := 4 + len(ns) + 4 + 4 + len(doc)
	totalLen := headerLen + bodyLen

	msg := make([]byte, totalLen)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(totalLen))   // msgLength
	binary.LittleEndian.PutUint32(msg[4:8], 1)                  // requestID
	binary.LittleEndian.PutUint32(msg[8:12], 0)                 // responseTo
	binary.LittleEndian.PutUint32(msg[12:16], 2004)             // opCode: OP_QUERY
	binary.LittleEndian.PutUint32(msg[16:20], 0)                // flags
	copy(msg[20:], ns)                                           // namespace
	off := 20 + len(ns)
	binary.LittleEndian.PutUint32(msg[off:off+4], 0)            // numberToSkip
	binary.LittleEndian.PutUint32(msg[off+4:off+8], 1)          // numberToReturn
	copy(msg[off+8:], doc)                                       // query document

	return msg
}

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
// Phase 1: lecture passive (SSH, SMTP, FTP, MySQL envoient en premier).
// Phase 2: si rien recu, envoie des probes protocolaires (Redis, PostgreSQL, AMQP).
// Retourne la banner brute ou "" si timeout/erreur.
func (s *TCPScanner) GrabBanner(ip string, port int, readTimeout time.Duration) string {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, s.ConnectTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Phase 1: lire la banner spontanee (le serveur envoie en premier)
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if n > 0 {
		return cleanBanner(buf[:n])
	}

	// Phase 2: pas de banner spontanee, essayer des probes protocolaires
	for _, probe := range serviceProbes {
		conn2, err := net.DialTimeout("tcp", addr, s.ConnectTimeout)
		if err != nil {
			continue
		}
		conn2.SetWriteDeadline(time.Now().Add(readTimeout))
		_, err = conn2.Write(probe.send)
		if err != nil {
			conn2.Close()
			continue
		}
		conn2.SetReadDeadline(time.Now().Add(readTimeout))
		n, err := conn2.Read(buf)
		conn2.Close()
		if n > 0 {
			banner := cleanBanner(buf[:n])
			if banner != "" {
				return probe.prefix + banner
			}
		}
	}

	return ""
}

// cleanBanner filtre les caracteres non-imprimables (garde ASCII 9,10,13,32-126).
func cleanBanner(raw []byte) string {
	var clean []byte
	for _, b := range raw {
		if b == 9 || b == 10 || b == 13 || (b >= 32 && b <= 126) {
			clean = append(clean, b)
		}
	}
	return string(clean)
}

// serviceProbe est une sonde protocolaire pour identifier un service qui n'envoie pas de banner spontanee.
type serviceProbe struct {
	send   []byte
	prefix string // prefixe ajoute a la banner pour identifier le protocole
}

// serviceProbes sont testes dans l'ordre quand le read passif echoue.
var serviceProbes = []serviceProbe{
	// Redis: INFO server -> redis_version:x.y.z (matchable par les patterns)
	{send: []byte("INFO server\r\n"), prefix: ""},
	// PostgreSQL: SSLRequest -> 'N' ou 'S', puis on lit l'erreur d'auth
	{send: []byte{0, 0, 0, 8, 4, 210, 22, 47}, prefix: "PostgreSQL SSL:"},
	// AMQP 0-9-1: protocol header -> connection.start (RabbitMQ/ActiveMQ)
	{send: []byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}, prefix: "AMQP:"},
	// MongoDB: isMaster query -> response with server info
	{send: mongoIsMasterMsg(), prefix: "MongoDB:"},
}
