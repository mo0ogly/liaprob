#!/usr/bin/env bash
# scan_live_targets.sh - Scanne les IPs collectees avec LiaProbe et mesure le taux de detection
# Usage: ./scan_live_targets.sh [--timeout 3000] [--parallel 3]
# Input: recette/live_targets.csv
# Output: recette/live_results/RECETTE_LIVE_YYYY-MM-DD_HHMMSS.md + .jsonl (audit trail)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIAPROBE_DIR="$(dirname "$SCRIPT_DIR")"
LIAPROBE_BIN="${LIAPROBE_DIR}/bin/liaprobe"
TARGETS_FILE="${SCRIPT_DIR}/live_targets.csv"
RESULTS_DIR="${SCRIPT_DIR}/live_results"
TIMESTAMP=$(date +%Y-%m-%d_%H%M%S)
REPORT_FILE="${RESULTS_DIR}/RECETTE_LIVE_${TIMESTAMP}.md"
AUDIT_FILE="${RESULTS_DIR}/RECETTE_LIVE_${TIMESTAMP}.jsonl"
SCAN_TIMEOUT=3000
PARALLEL=1

while [[ $# -gt 0 ]]; do
    case $1 in
        --timeout) SCAN_TIMEOUT=$2; shift 2 ;;
        --parallel) PARALLEL=$2; shift 2 ;;
        *) echo "Usage: $0 [--timeout MS] [--parallel N]"; exit 1 ;;
    esac
done

if [[ ! -x "$LIAPROBE_BIN" ]]; then
    echo "[ERROR] LiaProbe binary not found at $LIAPROBE_BIN"
    exit 1
fi
if [[ ! -f "$TARGETS_FILE" ]]; then
    echo "[ERROR] Targets file not found: $TARGETS_FILE"
    exit 1
fi

mkdir -p "$RESULTS_DIR"

total=$(tail -n +2 "$TARGETS_FILE" | grep -c '[^[:space:]]' || echo 0)
if [[ $total -eq 0 ]]; then
    echo "[ERROR] No targets in $TARGETS_FILE"
    exit 1
fi

liaprobe_version=$("$LIAPROBE_BIN" --help 2>&1 | head -1 | tr -d '\n\r' || echo "unknown")
scan_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "============================================================"
echo "  LiaProbe Live Recette Scanner"
echo "  Targets: $total | Timeout: ${SCAN_TIMEOUT}ms"
echo "  Binary: $LIAPROBE_BIN"
echo "  Version: $liaprobe_version"
echo "  Report: $REPORT_FILE"
echo "  Audit:  $AUDIT_FILE"
echo "============================================================"
echo ""

# Initialize audit trail header
echo "{\"type\":\"recette_start\",\"ts\":\"$scan_start\",\"targets\":$total,\"timeout_ms\":$SCAN_TIMEOUT,\"version\":\"$liaprobe_version\",\"binary\":\"$LIAPROBE_BIN\"}" > "$AUDIT_FILE"

detected=0
not_detected=0
errors=0

# Scan each target
idx=0
while IFS=',' read -r ip port technology category source; do
    [[ "$ip" == "ip" ]] && continue
    idx=$((idx + 1))

    printf "  [%3d/%d] %-25s %s:%s ... " "$idx" "$total" "$technology" "$ip" "$port"

    target_start=$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)
    start_epoch=$(date +%s%3N)

    # Run LiaProbe scan
    result_file="${RESULTS_DIR}/scan_${idx}_${technology// /_}.json"
    scan_output=$(timeout --signal=KILL 25 "$LIAPROBE_BIN" --ports "$port" --mode full --output json --timeout "$SCAN_TIMEOUT" "$ip" 2>/dev/null) || true

    end_epoch=$(date +%s%3N)
    duration_ms=$((end_epoch - start_epoch))

    if [[ -z "$scan_output" ]]; then
        echo "[ERROR] no output (${duration_ms}ms)"
        errors=$((errors + 1))
        python3 -c "
import json,sys
print(json.dumps({'type':'scan','idx':$idx,'ts':'$target_start','ip':'$ip','port':$port,'expected':'$technology','category':'$category','source':'$source','status':'ERROR','duration_ms':$duration_ms,'services':[],'banners':[],'ports_open':0}))
" >> "$AUDIT_FILE"
        continue
    fi

    echo "$scan_output" > "$result_file"

    # Parse scan output, write audit trail, and output console line - all in one Python call
    # This avoids bash corrupting JSON with control chars in banners
    console_line=$(echo "$scan_output" | python3 -c "
import json, sys

data = json.load(sys.stdin)
audit = {
    'type': 'scan', 'idx': $idx, 'ts': '$target_start',
    'ip': '$ip', 'port': $port, 'expected': '$technology',
    'category': '$category', 'source': '$source',
    'duration_ms': $duration_ms, 'result_file': '$result_file',
    'status': 'MISS', 'services': [], 'banners': [],
    'ports_open': 0, 'hosts_alive': 0,
    'scan_id': data.get('id', ''),
    'scan_duration_ms': data.get('stats', {}).get('duration_ms', 0),
}

for host in data.get('hosts', []):
    if host.get('alive'):
        audit['hosts_alive'] += 1
    for p in (host.get('open_ports') or []):
        audit['ports_open'] += 1
        banner = p.get('banner', '')
        if banner:
            audit['banners'].append({
                'port': p['port'],
                'banner': banner[:120].replace('\\r','').replace('\\n',' '),
                'protocol': p.get('protocol', 'tcp'),
            })
    for svc in (host.get('services') or []):
        name = svc.get('name', '')
        conf = svc.get('confidence', 0)
        if name and conf > 0:
            audit['status'] = 'DETECTED'
            audit['services'].append({
                'name': name, 'product': svc.get('product', ''),
                'version': svc.get('version', ''),
                'confidence': conf, 'pattern_id': svc.get('pattern_id', ''),
                'cpe': svc.get('cpe', ''), 'port': svc.get('port', 0),
            })

if audit['status'] == 'MISS' and audit['banners']:
    audit['status'] = 'BANNER'

# Write audit trail (safe JSON)
with open('$AUDIT_FILE', 'a') as af:
    af.write(json.dumps(audit, ensure_ascii=True) + '\\n')

# Console output
svcs = audit['services']
if audit['status'] == 'DETECTED':
    best = max(svcs, key=lambda s: s['confidence'])
    print(f'DETECTED|{best[\"name\"]}|{best[\"confidence\"]}|{best[\"pattern_id\"]}|{len(svcs)}')
elif audit['status'] == 'BANNER':
    b = audit['banners'][0]['banner'][:40]
    print(f'BANNER|{b}|0||')
else:
    print(f'MISS||||')
" 2>/dev/null)

    if [[ -z "$console_line" ]]; then
        echo "[ERROR] parse failed (${duration_ms}ms)"
        errors=$((errors + 1))
        python3 -c "
import json
with open('$AUDIT_FILE', 'a') as f:
    f.write(json.dumps({'type':'scan','idx':$idx,'ts':'$target_start','ip':'$ip','port':$port,'expected':'$technology','category':'$category','source':'$source','status':'PARSE_ERROR','duration_ms':$duration_ms,'services':[],'banners':[],'ports_open':0}) + '\n')
"
        continue
    fi

    status=$(echo "$console_line" | cut -d'|' -f1)
    case "$status" in
        DETECTED)
            det_name=$(echo "$console_line" | cut -d'|' -f2)
            det_conf=$(echo "$console_line" | cut -d'|' -f3)
            det_pattern=$(echo "$console_line" | cut -d'|' -f4)
            svc_count=$(echo "$console_line" | cut -d'|' -f5)
            echo "[DETECTED] $det_name (conf:$det_conf pattern:$det_pattern svcs:$svc_count ${duration_ms}ms)"
            detected=$((detected + 1))
            ;;
        BANNER)
            banner_text=$(echo "$console_line" | cut -d'|' -f2)
            echo "[BANNER] $banner_text (${duration_ms}ms)"
            detected=$((detected + 1))
            ;;
        *)
            echo "[MISS] (${duration_ms}ms)"
            not_detected=$((not_detected + 1))
            ;;
    esac

done < "$TARGETS_FILE"

scan_end=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Detection rate
if [[ $((detected + not_detected)) -gt 0 ]]; then
    rate=$(python3 -c "print(f'{$detected / ($detected + $not_detected) * 100:.1f}')")
else
    rate="0.0"
fi

# Write audit trail footer
echo "{\"type\":\"recette_end\",\"ts\":\"$scan_end\",\"detected\":$detected,\"missed\":$not_detected,\"errors\":$errors,\"rate\":\"${rate}%\"}" >> "$AUDIT_FILE"

# Generate report from audit trail
python3 << PYEOF > "$REPORT_FILE"
import json, sys
from collections import defaultdict

audit_file = "$AUDIT_FILE"

lines = []
with open(audit_file) as f:
    for line in f:
        try:
            lines.append(json.loads(line))
        except json.JSONDecodeError:
            pass

header = lines[0]
footer = lines[-1]
scans = [l for l in lines if l.get('type') == 'scan']

print(f"# Recette Live LiaProbe - {header['ts'][:10]}")
print()
print("## Resume")
print()
print("| Metrique | Valeur |")
print("|----------|--------|")
print(f"| Version LiaProbe | {header.get('version', '?')} |")
print(f"| Date debut | {header['ts']} |")
print(f"| Date fin | {footer['ts']} |")
print(f"| Total cibles | {header['targets']} |")
print(f"| Detectees (service ou banner) | {footer['detected']} |")
print(f"| Non detectees | {footer['missed']} |")
print(f"| Erreurs | {footer['errors']} |")
print(f"| **Taux de detection** | **{footer['rate']}** |")
print(f"| Timeout scan | {header['timeout_ms']}ms |")
print()

by_cat = defaultdict(list)
for s in scans:
    by_cat[s['category']].append(s)

print("## Resultats par categorie")
print()

for cat in sorted(by_cat.keys()):
    items = by_cat[cat]
    det = sum(1 for i in items if i['status'] in ('DETECTED', 'BANNER'))
    total_cat = len(items)
    rate = f"{det/total_cat*100:.0f}%" if total_cat > 0 else "N/A"
    print(f"### {cat} ({det}/{total_cat} = {rate})")
    print()
    print("| # | IP | Port | Attendu | Status | Detecte (best) | Conf | Pattern | Version | Duree | Banners | Services |")
    print("|---|-----|------|---------|--------|----------------|------|---------|---------|-------|---------|----------|")
    for s in items:
        svcs = s.get('services', [])
        banners = s.get('banners', [])
        best_name = best_conf = best_pattern = best_ver = ""
        if svcs:
            best = max(svcs, key=lambda x: x['confidence'])
            best_name = best['name']
            best_conf = f"{best['confidence']}"
            best_pattern = best['pattern_id']
            best_ver = best.get('version', '')
        elif banners:
            best_name = f"BANNER: {banners[0]['banner'][:30]}"
        status_icon = {"DETECTED": "OK", "BANNER": "BNR", "MISS": "MISS", "ERROR": "ERR"}.get(s['status'], s['status'])
        banner_summary = ", ".join(f":{b['port']} {b['banner'][:25]}" for b in banners[:2])
        svc_count = f"{len(svcs)}" if svcs else "0"
        print(f"| {s['idx']} | {s['ip']} | {s['port']} | {s['expected']} | {status_icon} | {best_name} | {best_conf} | {best_pattern} | {best_ver} | {s['duration_ms']}ms | {banner_summary} | {svc_count} |")
    print()

print("## Detail des detections")
print()
for s in scans:
    svcs = s.get('services', [])
    banners = s.get('banners', [])
    if not svcs and not banners:
        continue
    print(f"### #{s['idx']} {s['ip']}:{s['port']} ({s['expected']})")
    print()
    print(f"- **Timestamp** : {s['ts']}")
    print(f"- **Duree** : {s['duration_ms']}ms")
    print(f"- **Categorie** : {s['category']}")
    print(f"- **Source IP** : {s['source']}")
    print(f"- **Ports ouverts** : {s['ports_open']}")
    print(f"- **Status** : {s['status']}")
    if s.get('scan_id'):
        print(f"- **Scan ID** : {s['scan_id']}")
    if s.get('result_file'):
        print(f"- **JSON brut** : `{s['result_file']}`")
    if banners:
        print()
        print("**Banners captures :**")
        print()
        print("| Port | Protocol | Banner |")
        print("|------|----------|--------|")
        for b in banners:
            esc = b['banner'].replace('|', '\\|').replace('\n', ' ').replace('\r', '')
            print(f"| {b['port']} | {b['protocol']} | \`{esc}\` |")
    if svcs:
        print()
        print("**Services detectes :**")
        print()
        print("| Port | Service | Confidence | Pattern | Version | CPE |")
        print("|------|---------|------------|---------|---------|-----|")
        for svc in sorted(svcs, key=lambda x: -x['confidence']):
            print(f"| {svc['port']} | {svc['name']} | {svc['confidence']} | {svc['pattern_id']} | {svc.get('version','')} | {svc.get('cpe','')} |")
    print()

print("## Commande de reproduction")
print()
print("\`\`\`bash")
print("cd $LIAPROBE_DIR")
print("./recette/collect_live_ips.sh")
print(f"./recette/scan_live_targets.sh --timeout {header['timeout_ms']}")
print("\`\`\`")
PYEOF

echo ""
echo "============================================================"
echo "  RESULTATS"
echo "------------------------------------------------------------"
echo "  Detectees:     $detected / $total"
echo "  Non detectees: $not_detected / $total"
echo "  Erreurs:       $errors / $total"
echo "  TAUX:          ${rate}%"
echo "------------------------------------------------------------"
echo "  Rapport: $REPORT_FILE"
echo "  Audit:   $AUDIT_FILE"
echo "============================================================"
