#!/usr/bin/env bash
# Reproduces the technical audit of the Aeria platform (module 5).
#
# RULES OF ENGAGEMENT: scan only the Aeria platform you run yourself and your own workstation.
# The scanner is the nmap embedded in the Varys backend container (https://github.com/brinis-aya/varys);
# any host with nmap 7.9x works the same way.
set -euo pipefail
OUT=${OUT:-docs/audit/raw}
SCANNER=${SCANNER:-sentinelproof-backend-1}
AERIA_NET=${AERIA_NET:-aeria_default}
WORKSTATION_IP=${WORKSTATION_IP:?set WORKSTATION_IP to the LAN address of your own machine}
mkdir -p "$OUT"

# 1. internal view: the scanner joins the Aeria Docker network for the duration of the audit
docker network connect "$AERIA_NET" "$SCANNER" 2>/dev/null || true
SUBNET=$(docker network inspect "$AERIA_NET" -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}')
TARGETS=$(docker network inspect "$AERIA_NET" -f '{{range .Containers}}{{.IPv4Address}} {{end}}' | sed 's#/[0-9]*##g')
docker exec "$SCANNER" nmap -sV -Pn -p- --script mqtt-subscribe,banner -oN - $TARGETS > "$OUT/01-nmap-reseau-interne.txt"

# 2. MQTT anonymous access (from inside the broker container, harmless test topic)
docker exec aeria-mosquitto-1 mosquitto_pub -d -h 127.0.0.1 -q 1 -t 'aeria/sensors/AUDIT-TEST/measurements' \
    -m '{"audit":"test"}' > "$OUT/02-mqtt-acces-anonyme.txt" 2>&1 || true

# 3. LAN view of the workstation (Aeria ports + usual services)
docker exec "$SCANNER" nmap -sV -Pn -T4 \
    -p 22,80,135,139,443,445,1883,3389,5432,5440,8080,8081,8083,8084,8443,9200,55000 \
    -oN - "$WORKSTATION_IP" > "$OUT/03-nmap-poste-lan.txt"

# 4. Varys risk rules and tamper-evident evidence (same scans, with Aeria ports added)
PORTS="21,22,23,25,53,80,110,111,135,139,143,443,445,1433,1521,1883,2375,3306,3389,5432,5440,5900,6379,8080,8081,8083,8084,8443,9200,11211,27017"
for T in "$SUBNET" "$WORKSTATION_IP/32"; do
  docker exec -e SCAN_PORTS="$PORTS" "$SCANNER" python -c "
from app.services.scan_runner import start_scan
r = start_scan('network', '$T', 'aeria-security', wait=True); print(r.id, r.status, r.summary)"
done | tee "$OUT/04-varys-runs.txt"

# 5. application checks (security headers, cookies, exposed endpoints, password guessing)
python scripts/web_checks.py --backoffice http://127.0.0.1:8084 --forecast http://127.0.0.1:8083 \
    --out "$OUT/06-web.json"

docker network disconnect "$AERIA_NET" "$SCANNER" || true
echo "audit outputs in $OUT"
