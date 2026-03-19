package portdb

import (
	"testing"
)

func TestGuessServiceFromBanner(t *testing.T) {
	tests := []struct {
		banner  string
		want    string
	}{
		{"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6", "ssh"},
		{"220 (vsFTPd 3.0.5)", "ftp"},
		{"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0", "nginx"},
		{"HTTP/1.1 200 OK\r\nServer: Apache/2.4.58", "apache"},
		{"+OK Dovecot ready.", ""},  // no direct match for dovecot at root level
		{"220 mail.example.com ESMTP Postfix", "smtp"},
		{"5.7.1 MariaDB-1:11.2.2+maria~ubu2204", "mariadb"},
		{"-ERR unknown command", ""},
		{"", ""},
		{"Redis:7.2.4", "redis"},
		{"MongoDB server version: 7.0.5", "mongodb"},
	}

	for _, tt := range tests {
		got := GuessServiceFromBanner(tt.banner)
		if got != tt.want {
			t.Errorf("GuessServiceFromBanner(%q) = %q, want %q", tt.banner, got, tt.want)
		}
	}
}

func TestContextPortsForService(t *testing.T) {
	tests := []struct {
		service string
		wantMin int // minimum expected ports
	}{
		{"ssh", 2},
		{"mysql", 1},
		{"kubernetes", 3},
		{"unknown-service", 0},
	}

	for _, tt := range tests {
		got := ContextPortsForService(tt.service)
		if len(got) < tt.wantMin {
			t.Errorf("ContextPortsForService(%q) returned %d ports, want at least %d", tt.service, len(got), tt.wantMin)
		}
	}
}
