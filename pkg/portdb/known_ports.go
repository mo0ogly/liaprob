// Package portdb contains the knowledge base of ports, services, and scan profiles.
// Mapping port -> likely service, port -> relevant probes, preconfigured profiles.
package portdb

// CommonPorts are the ports scanned in fast mode (~60 ports).
// Values validated in LIA-SEC lab.
var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445,
	465, 587, 631, 636, 993, 995, 1433, 1521, 1883, 2049, 2181, 2375, 2376,
	3000, 3306, 3389, 4369, 4848, 5000, 5432, 5601, 5672, 5900, 5984,
	6379, 6443, 7001, 7070, 8080, 8081, 8082, 8443, 8500, 8888, 9000,
	9090, 9092, 9200, 9300, 10250, 10251, 10252, 27017, 27018, 50070,
}

// ContextExpansion defines additional ports to scan when a specific port is open.
// This is the core of "intelligent" scanning: no brute-force, contextual expansion.
var ContextExpansion = map[int][]int{
	// Windows / AD
	445: {135, 139, 389, 636, 88, 464, 3268, 3269, 5985, 5986},
	135: {139, 445, 389, 636},
	389: {636, 3268, 3269, 88, 464, 445},

	// Web
	80:   {8080, 8443, 3000, 5000, 9090, 443},
	443:  {8080, 8443, 3000, 5000, 9090, 80},
	8080: {8443, 80, 443, 9090, 3000},

	// SSH
	22: {2222, 2200},

	// Databases
	3306:  {5432, 1433, 27017, 6379, 5984},
	5432:  {3306, 1433, 27017, 6379},
	1433:  {3306, 5432, 27017},
	27017: {27018, 3306, 5432, 6379},
	6379:  {6380, 3306, 5432},

	// Message queues
	5672: {5671, 15672, 4369, 25672},
	9092: {2181, 9093, 8083},

	// Monitoring
	9090: {3000, 9093, 9100, 8086},
	3000: {9090, 5601, 8086},

	// Docker / K8s endpoints
	2375: {2376, 9000, 5000},
	6443: {10250, 10251, 10252, 2379, 2380},
}

// ServiceHints maps a port to the most likely service/product names.
// Used for sorting candidate patterns (pass 1 fast).
var ServiceHints = map[int][]string{
	21:    {"ftp", "vsftpd", "proftpd", "pure-ftpd"},
	22:    {"openssh", "dropbear", "ssh"},
	23:    {"telnet"},
	25:    {"smtp", "postfix", "exim", "sendmail"},
	53:    {"bind", "unbound", "dnsmasq"},
	80:    {"apache", "nginx", "iis", "lighttpd"},
	110:   {"pop3", "dovecot", "cyrus"},
	135:   {"rpc", "dce", "msrpc"},
	139:   {"netbios", "smb"},
	143:   {"imap", "dovecot", "cyrus"},
	389:   {"ldap", "activedirectory", "openldap", "adds"},
	443:   {"apache", "nginx", "iis", "lighttpd"},
	445:   {"samba", "smb", "cifs", "windows"},
	636:   {"ldaps", "ldap", "activedirectory", "adds"},
	993:   {"imap", "dovecot"},
	995:   {"pop3", "dovecot"},
	1433:  {"sql", "mssql"},
	1521:  {"oracle", "orcl"},
	1883:  {"mqtt", "mosquitto"},
	2375:  {"docker"},
	2376:  {"docker"},
	3000:  {"grafana", "gitea"},
	3306:  {"mysql", "mariadb"},
	3389:  {"rdp", "windows"},
	5432:  {"postgresql"},
	5672:  {"amqp", "rabbitmq"},
	5900:  {"vnc"},
	5984:  {"couchdb"},
	6379:  {"redis"},
	6443:  {"kubernetes", "k8s"},
	7001:  {"weblogic"},
	8080:  {"tomcat", "jenkins", "jetty"},
	8443:  {"tomcat", "pan", "forti"},
	8888:  {"jupyter"},
	9000:  {"sonarqube"},
	9090:  {"prometheus"},
	9092:  {"kafka"},
	9200:  {"elasticsearch"},
	27017: {"mongodb"},
}
