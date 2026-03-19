package portdb

import "strings"

// GuessServiceFromBanner attempts to identify a service from a raw banner.
// Returns the service name or "" if unknown.
func GuessServiceFromBanner(banner string) string {
	lower := strings.ToLower(banner)

	// Banner patterns -> service name
	patterns := []struct {
		match   string
		service string
	}{
		{"openssh", "ssh"},
		{"ssh-", "ssh"},
		{"apache", "apache"},
		{"nginx", "nginx"},
		{"microsoft-iis", "iis"},
		{"vsftpd", "ftp"},
		{"proftpd", "ftp"},
		{"esmtp", "smtp"},
		{"smtp", "smtp"},
		{"postfix", "smtp"},
		{"exim", "smtp"},
		{"220 ", "ftp"},      // FTP greeting (after SMTP-specific checks)
		{"220-", "ftp"},
		{"mysql", "mysql"},
		{"mariadb", "mariadb"},
		{"postgresql", "postgresql"},
		{"redis", "redis"},
		{"+redis", "redis"},
		{"mongodb", "mongodb"},
		{"elastic", "elasticsearch"},
		{"rabbitmq", "rabbitmq"},
		{"amqp", "rabbitmq"},
		{"kafka", "kafka"},
		{"jenkins", "jenkins"},
		{"tomcat", "tomcat"},
		{"grafana", "grafana"},
		{"prometheus", "prometheus"},
		{"docker", "docker"},
		{"kubernetes", "kubernetes"},
		{"samba", "samba"},
		{"ldap", "ldap"},
		{"vnc", "vnc"},
		{"rdp", "rdp"},
		{"microsoft-ds", "smb"},
		{"http", "http"},
	}

	for _, p := range patterns {
		if strings.Contains(lower, p.match) {
			return p.service
		}
	}

	return ""
}

// ContextPortsForService returns contextual ports for a service name.
func ContextPortsForService(service string) []int {
	lower := strings.ToLower(service)

	servicePortMap := map[string][]int{
		"ssh":           {22, 2222, 2200},
		"http":          {80, 8080, 8443, 3000, 5000, 9090, 443},
		"apache":        {80, 443, 8080, 8443},
		"nginx":         {80, 443, 8080, 8443},
		"iis":           {80, 443, 8080, 8443},
		"ftp":           {21, 990},
		"smtp":          {25, 465, 587},
		"mysql":         {3306, 3307},
		"mariadb":       {3306, 3307},
		"postgresql":    {5432, 5433},
		"redis":         {6379, 6380},
		"mongodb":       {27017, 27018, 27019},
		"elasticsearch": {9200, 9300},
		"rabbitmq":      {5672, 5671, 15672, 4369},
		"kafka":         {9092, 2181, 9093},
		"jenkins":       {8080, 8443, 50000},
		"tomcat":        {8080, 8443, 8009},
		"grafana":       {3000, 3001},
		"prometheus":    {9090, 9093, 9100},
		"docker":        {2375, 2376, 9000, 5000},
		"kubernetes":    {6443, 10250, 10251, 10252, 2379},
		"ldap":          {389, 636, 3268, 3269},
		"smb":           {445, 135, 139},
		"samba":         {445, 135, 139},
		"vnc":           {5900, 5901, 5902},
		"rdp":           {3389},
	}

	if ports, ok := servicePortMap[lower]; ok {
		return ports
	}
	return nil
}
