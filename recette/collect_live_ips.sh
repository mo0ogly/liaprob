#!/usr/bin/env bash
# collect_live_ips.sh - Collecte 3 IPs live par technologie depuis Netlas.io (gratuit)
# Usage: ./collect_live_ips.sh [--dry-run] [--limit N] [--category CAT]
# Output: recette/live_targets.csv (ip,port,technology,category,source)
#
# Netlas.io: 50 requetes/jour, pas de cle API requise pour les recherches basiques
# Fallback: IPs connues de services publics si Netlas rate-limite

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_FILE="${SCRIPT_DIR}/live_targets.csv"
RESULTS_DIR="${SCRIPT_DIR}/live_results"
NETLAS_API="https://app.netlas.io/api/responses"
IPS_PER_TECH=3
DRY_RUN=false
FILTER_CAT=""
DELAY=2  # seconds between API calls (respect rate limits)

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run) DRY_RUN=true; shift ;;
        --limit) IPS_PER_TECH=$2; shift 2 ;;
        --category) FILTER_CAT=$2; shift 2 ;;
        *) echo "Usage: $0 [--dry-run] [--limit N] [--category CAT]"; exit 1 ;;
    esac
done

mkdir -p "$RESULTS_DIR"

# Technology definitions: category|product|netlas_query|ports
TECHNOLOGIES=(
    # Databases
    "databases|MySQL|tag.name:mysql|3306"
    "databases|MariaDB|tag.name:mariadb|3306"
    "databases|PostgreSQL|tag.name:postgresql|5432"
    "databases|Elasticsearch|tag.name:elasticsearch|9200"
    "databases|Redis|tag.name:redis|6379"
    "databases|MongoDB|tag.name:mongodb|27017"
    # CI/CD
    "ci-cd|Jenkins|http.headers.x_jenkins|8080"
    "ci-cd|GitLab|http.title:GitLab|80"
    "ci-cd|SonarQube|http.title:SonarQube|9000"
    # CMS
    "cms|WordPress|http.headers.x_powered_by:WordPress OR http.body:wp-content|80"
    "cms|Drupal|http.headers.x_generator:Drupal|80"
    # Monitoring
    "monitoring|Grafana|http.title:Grafana|3000"
    "monitoring|Kibana|http.title:Kibana|5601"
    "monitoring|Zabbix|http.title:Zabbix|80"
    # Web servers
    "web-servers|Nginx|tag.name:nginx|80"
    "web-servers|Apache|tag.name:apache|80"
    "web-servers|LiteSpeed|http.headers.server:LiteSpeed|80"
    "web-servers|lighttpd|tag.name:lighttpd|80"
    # Web app servers
    "web-appservers|Jetty|http.headers.server:Jetty|8080"
    "web-appservers|Gunicorn|http.headers.server:gunicorn|8000"
    # Proxies
    "web-proxies|Squid|tag.name:squid|3128"
    "web-proxies|Varnish|http.headers.via:varnish|80"
    # Containers
    "containers|Docker Registry|http.headers.docker_distribution_api_version|5000"
    "containers|Consul|http.title:Consul|8500"
    # SSH
    "ssh|OpenSSH|tag.name:openssh|22"
    # Mail
    "mail-servers|Postfix|tag.name:postfix|25"
    "mail-servers|Dovecot|tag.name:dovecot|143"
    # FTP
    "ftp|ProFTPD|tag.name:proftpd|21"
    "ftp|vsftpd|tag.name:vsftpd|21"
    "ftp|Pure-FTPd|tag.name:pure-ftpd|21"
    # DNS
    "dns|BIND|tag.name:bind|53"
    # Messaging
    "messaging|RabbitMQ|http.title:RabbitMQ|15672"
    # Storage
    "storage|Nextcloud|http.title:Nextcloud|80"
    # IoT
    "iot|CUPS|http.title:CUPS|631"
    # API Frameworks
    "api-frameworks|Django|http.headers.x_frame_options:DENY AND http.headers.server:WSGIServer|8000"
    # Security
    "security|OpenVPN|tag.name:openvpn|1194"
)

query_netlas() {
    local query="$1"
    local encoded_query
    encoded_query=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$query'))")

    curl -s --connect-timeout 10 --max-time 15 \
        "${NETLAS_API}/?q=${encoded_query}&start=0&indices=&fields=ip,port" \
        2>/dev/null
}

extract_ips() {
    local json_data="$1"
    local count="$2"
    local default_port="$3"

    echo "$json_data" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    items = data.get('items', [])
    seen = set()
    n = 0
    limit = int('$count')
    fallback_port = int('$default_port')
    for item in items:
        d = item.get('data', {})
        ip = d.get('ip', '')
        port = d.get('port', fallback_port)
        if ip and ip not in seen and n < limit:
            if ip.startswith('10.') or ip.startswith('192.168.') or ip.startswith('172.'):
                continue
            seen.add(ip)
            print(f'{ip},{port}')
            n += 1
except:
    pass
" 2>/dev/null
}

# Header
echo "ip,port,technology,category,source" > "$OUTPUT_FILE"

total=${#TECHNOLOGIES[@]}
collected=0
failed=0
skipped=0

echo "============================================================"
echo "  LiaProbe Live IP Collector"
echo "  Technologies: $total | IPs/tech: $IPS_PER_TECH"
echo "  Source: Netlas.io (gratuit, 50 req/jour)"
echo "============================================================"
echo ""

for entry in "${TECHNOLOGIES[@]}"; do
    IFS='|' read -r category product query default_port <<< "$entry"

    # Filter by category if specified
    if [[ -n "$FILTER_CAT" && "$category" != "$FILTER_CAT" ]]; then
        skipped=$((skipped + 1))
        continue
    fi

    printf "  [%2d/%d] %-25s " "$((collected + failed + skipped + 1))" "$total" "$product"

    if $DRY_RUN; then
        echo "[DRY-RUN] query: $query"
        continue
    fi

    # Query Netlas
    response=$(query_netlas "$query" "$IPS_PER_TECH")

    if [[ -z "$response" ]] || echo "$response" | grep -q '"error"'; then
        echo "[FAIL] API error"
        failed=$((failed + 1))
        sleep "$DELAY"
        continue
    fi

    # Extract IPs
    ips=$(extract_ips "$response" "$IPS_PER_TECH" "$default_port")

    if [[ -z "$ips" ]]; then
        echo "[FAIL] 0 IPs"
        failed=$((failed + 1))
    else
        count=0
        while IFS=',' read -r ip port; do
            echo "${ip},${port},${product},${category},netlas" >> "$OUTPUT_FILE"
            count=$((count + 1))
        done <<< "$ips"
        echo "[OK] ${count} IPs"
        collected=$((collected + count))
    fi

    sleep "$DELAY"
done

echo ""
echo "============================================================"
echo "  Resultats"
echo "  Collectees: $collected IPs"
echo "  Echecs: $failed technologies"
echo "  Skipped: $skipped"
echo "  Fichier: $OUTPUT_FILE"
echo "============================================================"

if [[ $collected -gt 0 ]]; then
    echo ""
    echo "  Prochaine etape: lancer LiaProbe sur ces cibles"
    echo "  ./recette/scan_live_targets.sh"
fi
