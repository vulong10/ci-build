#!/usr/bin/env bash
set -uo pipefail
B=https://app-tbl-reporting-prod.azurewebsites.net
echo "### root"
curl -sS -o /tmp/r -w "HTTP %{http_code}  ct=%{content_type}\n" "$B/" --max-time 25; head -c 1200 /tmp/r; echo
for P in /healthz /api /api/v1 /internal /internal/debug /openapi.json /docs /swagger /report /render /api/v1/reports /api/v1/reports/render /api/v1/shipments /debug /env /config /status /version /robots.txt; do
  C=$(curl -sS -o /tmp/r -w "%{http_code}" "$B$P" --max-time 15 || echo ERR)
  if [ "$C" != "404" ]; then
    echo "--- GET $P -> $C"; head -c 500 /tmp/r; echo
  fi
done
echo
echo "### POST probes"
for P in /api/v1/reports/render /render /report; do
  C=$(curl -sS -o /tmp/r -w "%{http_code}" -X POST "$B$P" -H 'Content-Type: application/json' -d '{}' --max-time 15 || echo ERR)
  echo "--- POST $P -> $C"; head -c 500 /tmp/r; echo
done
echo "=== done ==="