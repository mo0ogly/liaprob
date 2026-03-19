package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Target validation (OWASP) -- pre-compiled regex, strict whitelist.
var (
	validIPv4Regex     = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	validHostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	validCIDRRegex     = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:3[0-2]|[12]?[0-9])$`)
)

// IsValidTarget validates that a target is an allowed format (IPv4, hostname, CIDR).
// OWASP Security: NEVER shell injection, validation BEFORE any connect.
func IsValidTarget(target string) bool {
	if len(target) == 0 || len(target) > 255 {
		return false
	}
	return validIPv4Regex.MatchString(target) ||
		validHostnameRegex.MatchString(target) ||
		validCIDRRegex.MatchString(target)
}

// IsPrivateIP retourne true si l'IP est RFC1918 (reseau prive).
// Utilise pour le warning "IP publique detectee" dans le journal.
func IsPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	privateRanges := []struct {
		network *net.IPNet
	}{
		{mustParseCIDR("10.0.0.0/8")},
		{mustParseCIDR("172.16.0.0/12")},
		{mustParseCIDR("192.168.0.0/16")},
		{mustParseCIDR("127.0.0.0/8")},
	}
	for _, r := range privateRanges {
		if r.network.Contains(parsed) {
			return true
		}
	}
	return false
}

func mustParseCIDR(s string) *net.IPNet {
	_, network, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("invalid CIDR constant: %s", s))
	}
	return network
}

// ExpandTargets transforme une liste de cibles brutes en liste de Target resolus.
// Supporte : IPv4, CIDR, hostname (avec resolution DNS).
func ExpandTargets(rawTargets []string, maxSubdomains int) ([]Target, error) {
	var targets []Target
	seen := make(map[string]bool)

	for _, raw := range rawTargets {
		raw = strings.TrimSpace(raw)
		if !IsValidTarget(raw) {
			continue
		}

		if validCIDRRegex.MatchString(raw) {
			// Expansion CIDR
			cidrTargets, err := expandCIDR(raw)
			if err != nil {
				continue
			}
			for _, t := range cidrTargets {
				if !seen[t.IP] {
					seen[t.IP] = true
					targets = append(targets, t)
				}
			}
		} else if validIPv4Regex.MatchString(raw) {
			// IP directe
			if !seen[raw] {
				seen[raw] = true
				hostname := reverseDNS(raw)
				targets = append(targets, Target{IP: raw, Hostname: hostname})
			}
		} else {
			// Hostname -> resolution DNS
			ips, err := net.LookupHost(raw)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				if !seen[ip] {
					seen[ip] = true
					targets = append(targets, Target{IP: ip, Hostname: raw})
				}
			}
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets after expansion")
	}
	return targets, nil
}

// expandCIDR genere toutes les IPs d'un bloc CIDR (max 65536).
func expandCIDR(cidr string) ([]Target, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var targets []Target
	ones, bits := ipNet.Mask.Size()
	if bits-ones > 16 {
		return nil, fmt.Errorf("CIDR block too large: /%d (max /16)", ones)
	}

	for current := ip.Mask(ipNet.Mask); ipNet.Contains(current); incrementIP(current) {
		targets = append(targets, Target{IP: current.String()})
		if len(targets) > 65536 {
			break
		}
	}

	// Retirer network address et broadcast (pour /24+)
	if ones >= 24 && len(targets) > 2 {
		targets = targets[1 : len(targets)-1]
	}
	return targets, nil
}

func incrementIP(ip net.IP) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	val := binary.BigEndian.Uint32(ip4)
	val++
	binary.BigEndian.PutUint32(ip4, val)
}

// reverseDNS tente une resolution DNS inverse. Retourne "" si echec.
func reverseDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
