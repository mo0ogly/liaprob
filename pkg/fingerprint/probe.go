package fingerprint

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mo0ogly/liaprobe/pkg/config"
)

// ProbeExecutor orchestrates the execution of probes defined in patterns.
type ProbeExecutor struct {
	config           config.FingerprintConfig
	httpClient       *http.Client
	noRedirectClient *http.Client
	tlsConfig        *tls.Config

	// Optional logger for debug messages.
	OnDebug func(component, action, details string)
}

// NewProbeExecutor creates an executor with the given configuration.
func NewProbeExecutor(cfg config.FingerprintConfig) *ProbeExecutor {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Lab/internal services
		},
		MaxIdleConns:           20,
		IdleConnTimeout:        30 * time.Second,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 1 << 20, // 1MB max headers
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.HTTPTimeoutMs) * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				return fmt.Errorf("cross-domain redirect blocked: %s -> %s", via[0].URL.Host, req.URL.Host)
			}
			return nil
		},
	}

	noRedirectClient := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.HTTPTimeoutMs) * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &ProbeExecutor{
		config:           cfg,
		httpClient:       client,
		noRedirectClient: noRedirectClient,
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

// ExecuteProbes execute tous les probes d'un pattern contre un host:port.
// Remplit le CollectedServiceData avec les reponses.
func (pe *ProbeExecutor) ExecuteProbes(ctx context.Context, host string, port int, probes []PatternProbe, data *CollectedServiceData) {
	if data.HTTPResponses == nil {
		data.HTTPResponses = make(map[string]*HTTPProbeResponse)
	}
	if data.TCPResponses == nil {
		data.TCPResponses = make(map[string]*TCPProbeResponse)
	}
	if data.UDPResponses == nil {
		data.UDPResponses = make(map[string]*UDPProbeResponse)
	}

	probesExecuted := 0
	for _, probe := range probes {
		if probesExecuted >= pe.config.MaxProbesPerService {
			break
		}

		if len(probe.Ports) > 0 && !containsInt(probe.Ports, port) {
			continue
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		switch probe.Layer {
		case "L7_HTTP":
			resp, err := pe.executeHTTPProbe(ctx, host, port, probe)
			if err != nil {
				pe.debug("FINGERPRINT_PROBE", "HTTP_PROBE_FAILED",
					fmt.Sprintf("Probe %s on %s:%d failed: %v", probe.ID, host, port, err))
				continue
			}
			data.HTTPResponses[probe.ID] = resp

		case "L4_TCP":
			resp, err := pe.executeTCPProbe(ctx, host, port, probe)
			if err != nil {
				pe.debug("FINGERPRINT_PROBE", "TCP_PROBE_FAILED",
					fmt.Sprintf("Probe %s on %s:%d failed: %v", probe.ID, host, port, err))
				continue
			}
			data.TCPResponses[probe.ID] = resp

		case "L4_TCP_HEX":
			resp, err := pe.executeTCPHexProbe(ctx, host, port, probe)
			if err != nil {
				pe.debug("FINGERPRINT_PROBE", "TCP_HEX_PROBE_FAILED",
					fmt.Sprintf("Probe %s on %s:%d failed: %v", probe.ID, host, port, err))
				continue
			}
			data.TCPResponses[probe.ID] = resp

		case "TLS_CERT":
			cert, err := pe.readTLSCert(ctx, host, port)
			if err != nil {
				pe.debug("FINGERPRINT_PROBE", "TLS_PROBE_FAILED",
					fmt.Sprintf("TLS cert read on %s:%d failed: %v", host, port, err))
				continue
			}
			data.TLSCert = cert

		case "L4_UDP":
			resp, err := pe.executeUDPProbe(ctx, host, port, probe)
			if err != nil {
				pe.debug("FINGERPRINT_PROBE", "UDP_PROBE_FAILED",
					fmt.Sprintf("Probe %s on %s:%d failed: %v", probe.ID, host, port, err))
				continue
			}
			data.UDPResponses[probe.ID] = resp

		case "L4_UDP_SSDP":
			if data.SSDPResponse != nil {
				continue
			}
			resp, err := pe.executeSSDP(ctx, host)
			if err != nil {
				pe.debug("FINGERPRINT_PROBE", "SSDP_PROBE_FAILED",
					fmt.Sprintf("SSDP M-SEARCH on %s:1900 failed: %v", host, err))
				continue
			}
			data.SSDPResponse = resp

		case "L4_UDP_MDNS":
			if data.MDNSResponses == nil {
				data.MDNSResponses = make(map[string]*MDNSProbeResponse)
			}
			resp, err := pe.executeMDNSProbe(ctx, host, probe)
			if err != nil {
				pe.debug("FINGERPRINT_PROBE", "MDNS_PROBE_FAILED",
					fmt.Sprintf("Probe %s mDNS on %s:5353 failed: %v", probe.ID, host, err))
				continue
			}
			data.MDNSResponses[probe.ID] = resp
		}

		probesExecuted++
	}
}

// executeHTTPProbe envoie une requete HTTP et retourne la reponse.
func (pe *ProbeExecutor) executeHTTPProbe(ctx context.Context, host string, port int, probe PatternProbe) (*HTTPProbeResponse, error) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d%s", scheme, host, port, probe.Path)
	method := probe.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if probe.Body != "" {
		bodyReader = strings.NewReader(probe.Body)
	}

	timeout := time.Duration(pe.config.HTTPTimeoutMs) * time.Millisecond
	if probe.TimeoutMs > 0 {
		timeout = time.Duration(probe.TimeoutMs) * time.Millisecond
	}
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "LiaProbe/1.0 Fingerprint Engine")
	req.Header.Set("Accept", "*/*")

	if probe.ContentType != "" {
		req.Header.Set("Content-Type", probe.ContentType)
	}

	for k, v := range probe.Headers {
		req.Header.Set(k, v)
	}

	httpClient := pe.httpClient
	if probe.FollowRedirects != nil && !*probe.FollowRedirects {
		httpClient = pe.noRedirectClient
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		// Retry avec HTTPS si HTTP echoue et port non standard
		if scheme == "http" && port != 80 {
			url = fmt.Sprintf("https://%s:%d%s", host, port, probe.Path)
			req2, _ := http.NewRequestWithContext(probeCtx, method, url, bodyReader)
			if req2 != nil {
				req2.Header = req.Header
				resp2, err2 := httpClient.Do(req2)
				if err2 != nil {
					return nil, fmt.Errorf("HTTP and HTTPS both failed: %w", err)
				}
				resp = resp2
			}
		}
		if resp == nil {
			return nil, err
		}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, int64(pe.config.MaxBodySize)))
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	cookies := make(map[string]string)
	for _, c := range resp.Cookies() {
		cookies[c.Name] = c.Value
	}

	return &HTTPProbeResponse{
		StatusCode: resp.StatusCode,
		Headers:    headers,
		Body:       string(bodyBytes),
		Cookies:    cookies,
	}, nil
}

// executeTCPProbe envoie des donnees texte via TCP et lit la reponse.
func (pe *ProbeExecutor) executeTCPProbe(ctx context.Context, host string, port int, probe PatternProbe) (*TCPProbeResponse, error) {
	timeout := time.Duration(pe.config.TCPTimeoutMs) * time.Millisecond
	if probe.TimeoutMs > 0 {
		timeout = time.Duration(probe.TimeoutMs) * time.Millisecond
	}
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TCP connect failed: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	var allBytes []byte
	buf := make([]byte, pe.config.MaxBannerSize)

	// Pour les protocoles a banniere spontanee (SMTP, FTP, IMAP, POP3)
	if probe.ReadFirst && probe.Send != "" {
		n, err := conn.Read(buf)
		if err != nil && n == 0 {
			return nil, fmt.Errorf("TCP read_first failed: %w", err)
		}
		allBytes = append(allBytes, buf[:n]...)
	}

	if probe.Send != "" {
		_, err := conn.Write([]byte(probe.Send))
		if err != nil {
			return nil, fmt.Errorf("TCP send failed: %w", err)
		}
	}

	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		if len(allBytes) > 0 {
			return &TCPProbeResponse{
				Data:    string(allBytes),
				DataHex: hex.EncodeToString(allBytes),
				Bytes:   allBytes,
			}, nil
		}
		return nil, fmt.Errorf("TCP read failed: %w", err)
	}
	allBytes = append(allBytes, buf[:n]...)

	return &TCPProbeResponse{
		Data:    string(allBytes),
		DataHex: hex.EncodeToString(allBytes),
		Bytes:   allBytes,
	}, nil
}

// executeTCPHexProbe envoie des donnees binaires (hex) via TCP.
func (pe *ProbeExecutor) executeTCPHexProbe(ctx context.Context, host string, port int, probe PatternProbe) (*TCPProbeResponse, error) {
	timeout := time.Duration(pe.config.TCPTimeoutMs) * time.Millisecond
	if probe.TimeoutMs > 0 {
		timeout = time.Duration(probe.TimeoutMs) * time.Millisecond
	}
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TCP connect failed: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if probe.SendHex != "" {
		hexData, err := hex.DecodeString(probe.SendHex)
		if err != nil {
			return nil, fmt.Errorf("invalid hex data: %w", err)
		}
		_, err = conn.Write(hexData)
		if err != nil {
			return nil, fmt.Errorf("TCP hex send failed: %w", err)
		}
	}

	buf := make([]byte, pe.config.MaxBannerSize)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("TCP hex read failed: %w", err)
	}

	responseBytes := buf[:n]
	return &TCPProbeResponse{
		Data:    string(responseBytes),
		DataHex: hex.EncodeToString(responseBytes),
		Bytes:   responseBytes,
	}, nil
}

// readTLSCert lit le certificat TLS d'un service.
func (pe *ProbeExecutor) readTLSCert(ctx context.Context, host string, port int) (*TLSCertInfo, error) {
	timeout := time.Duration(pe.config.TLSTimeoutMs) * time.Millisecond

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := tls.Dialer{
		Config: pe.tlsConfig,
		NetDialer: &net.Dialer{
			Timeout: timeout,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("not a TLS connection")
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates")
	}

	cert := state.PeerCertificates[0]

	return &TLSCertInfo{
		CommonName: cert.Subject.CommonName,
		SANs:       cert.DNSNames,
		Issuer:     cert.Issuer.CommonName,
		NotBefore:  cert.NotBefore.Format(time.RFC3339),
		NotAfter:   cert.NotAfter.Format(time.RFC3339),
		Serial:     cert.SerialNumber.String(),
	}, nil
}

// executeUDPProbe envoie des donnees via UDP et lit la reponse.
func (pe *ProbeExecutor) executeUDPProbe(ctx context.Context, host string, port int, probe PatternProbe) (*UDPProbeResponse, error) {
	timeout := time.Duration(pe.config.TCPTimeoutMs) * time.Millisecond
	if probe.TimeoutMs > 0 {
		timeout = time.Duration(probe.TimeoutMs) * time.Millisecond
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("UDP dial failed: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Envoyer les donnees (texte ou hex)
	if probe.SendHex != "" {
		hexData, err := hex.DecodeString(probe.SendHex)
		if err != nil {
			return nil, fmt.Errorf("invalid hex data: %w", err)
		}
		_, err = conn.Write(hexData)
		if err != nil {
			return nil, fmt.Errorf("UDP send hex failed: %w", err)
		}
	} else if probe.Send != "" {
		_, err = conn.Write([]byte(probe.Send))
		if err != nil {
			return nil, fmt.Errorf("UDP send failed: %w", err)
		}
	}

	buf := make([]byte, pe.config.MaxBannerSize)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("UDP read failed: %w", err)
	}

	responseBytes := buf[:n]
	// Determiner si le contenu est printable
	data := ""
	printable := true
	for _, b := range responseBytes {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			printable = false
			break
		}
	}
	if printable {
		data = string(responseBytes)
	}

	return &UDPProbeResponse{
		Data:    data,
		DataHex: hex.EncodeToString(responseBytes),
		Bytes:   responseBytes,
	}, nil
}

// executeSSDP envoie un M-SEARCH SSDP unicast.
func (pe *ProbeExecutor) executeSSDP(ctx context.Context, host string) (*SSDPProbeResponse, error) {
	timeout := time.Duration(pe.config.SSDPTimeoutMs) * time.Millisecond

	addr := fmt.Sprintf("%s:1900", host)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("SSDP dial failed: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	msearch := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: " + host + ":1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n"

	_, err = conn.Write([]byte(msearch))
	if err != nil {
		return nil, fmt.Errorf("SSDP send failed: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("SSDP read failed: %w", err)
	}

	raw := string(buf[:n])
	headers := make(map[string]string)
	for _, line := range strings.Split(raw, "\r\n") {
		if idx := strings.Index(line, ": "); idx > 0 {
			key := strings.ToUpper(strings.TrimSpace(line[:idx]))
			val := strings.TrimSpace(line[idx+2:])
			headers[key] = val
		}
	}

	return &SSDPProbeResponse{
		Headers: headers,
		RawData: raw,
	}, nil
}

// executeMDNSProbe envoie une requete mDNS unicast sur le port 5353.
func (pe *ProbeExecutor) executeMDNSProbe(ctx context.Context, host string, probe PatternProbe) (*MDNSProbeResponse, error) {
	timeout := time.Duration(pe.config.SSDPTimeoutMs) * time.Millisecond
	if probe.TimeoutMs > 0 {
		timeout = time.Duration(probe.TimeoutMs) * time.Millisecond
	}

	addr := fmt.Sprintf("%s:5353", host)
	conn, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("mDNS dial failed: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// DNS PTR query pour _services._dns-sd._udp.local
	dnsQuery := buildMDNSQuery()
	_, err = conn.Write(dnsQuery)
	if err != nil {
		return nil, fmt.Errorf("mDNS send failed: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return nil, fmt.Errorf("mDNS read failed: %w", err)
	}

	return parseMDNSResponse(buf[:n]), nil
}

// buildMDNSQuery construit une requete DNS PTR pour _services._dns-sd._udp.local.
func buildMDNSQuery() []byte {
	// Transaction ID (0x0000 pour mDNS), Flags (standard query), 1 question
	query := []byte{
		0x00, 0x00, // Transaction ID
		0x00, 0x00, // Flags: standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
	}
	// _services._dns-sd._udp.local PTR
	labels := []string{"_services", "_dns-sd", "_udp", "local"}
	for _, l := range labels {
		query = append(query, byte(len(l)))
		query = append(query, []byte(l)...)
	}
	query = append(query, 0x00)       // Root label
	query = append(query, 0x00, 0x0C) // Type PTR
	query = append(query, 0x00, 0x01) // Class IN
	return query
}

// parseMDNSResponse parse la reponse DNS brute.
func parseMDNSResponse(data []byte) *MDNSProbeResponse {
	resp := &MDNSProbeResponse{
		TXTRecords: make(map[string]string),
	}

	// Extraction simplifiee des noms DNS de la reponse
	var names []string
	i := 12 // Skip DNS header
	for i < len(data) {
		name, newPos := extractDNSName(data, i)
		if name != "" && newPos > i {
			names = append(names, name)
			// Detecter les services (noms commencant par _)
			if strings.HasPrefix(name, "_") {
				resp.Services = append(resp.Services, name)
			}
		}
		// Avancer au prochain record (skip les champs fixes du RR)
		if newPos+10 < len(data) {
			rdLength := int(data[newPos+8])<<8 | int(data[newPos+9])
			i = newPos + 10 + rdLength
		} else {
			break
		}
	}

	resp.RawNames = strings.Join(names, "\n")
	return resp
}

// extractDNSName extrait un nom DNS depuis un message.
func extractDNSName(data []byte, offset int) (string, int) {
	var parts []string
	pos := offset
	jumped := false
	originalPos := offset

	for pos < len(data) {
		length := int(data[pos])
		if length == 0 {
			pos++
			break
		}
		// Compression pointer
		if length&0xC0 == 0xC0 {
			if pos+1 >= len(data) {
				break
			}
			ptr := int(data[pos]&0x3F)<<8 | int(data[pos+1])
			if !jumped {
				originalPos = pos + 2
			}
			pos = ptr
			jumped = true
			continue
		}
		if pos+1+length > len(data) {
			break
		}
		parts = append(parts, string(data[pos+1:pos+1+length]))
		pos += 1 + length
	}

	if jumped {
		return strings.Join(parts, "."), originalPos
	}
	return strings.Join(parts, "."), pos
}

// debug appelle le logger debug optionnel.
func (pe *ProbeExecutor) debug(component, action, details string) {
	if pe.OnDebug != nil {
		pe.OnDebug(component, action, details)
	}
}
