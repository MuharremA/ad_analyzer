#!/bin/bash
SCRIPT_DIR="/root/ad_analyzer"
DC="192.168.56.10"
DOMAIN="lab.local"
USER="Administrator"
PASS="Szma185991."

cd "$SCRIPT_DIR"
source venv/bin/activate
fuser -k 8080/tcp 2>/dev/null
sleep 1

python3 ad_analyzer.py --dc "$DC" --domain "$DOMAIN" -u "$USER" -p "$PASS" "$@"

python3 "$SCRIPT_DIR/rapor_server.py" &
sleep 2

echo ""
echo "  Rapor hazir: http://localhost:8080"
echo "  Durdurmak icin: Ctrl+C"

wait
