#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, time, urllib.request, urllib.parse
def http(url, data=None, headers=None, method=None, js=None):
    h=dict(headers or {}); body=None
    if js is not None: body=json.dumps(js).encode(); h["Content-Type"]="application/json"
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
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/sync-service-principal?api-version=7.4",
          headers={"Authorization":"Bearer "+KVT})
c=json.loads(jg(b)["value"])
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
  {"client_id":c["appId"],"client_secret":c["clientSecret"],
   "scope":"https://graph.microsoft.com/.default","grant_type":"client_credentials"})
SYN=jg(b)["access_token"]; HS={"Authorization":"Bearer "+SYN}

TARGETS=[("tbl-legacy-admin","891fb158-e02c-4428-a885-53b811f369c0","22a3fb7e-860a-4708-9e50-3d36aa21191c"),
         ("tbl-directory-sync","7c2e61eb-f928-45cd-99c9-20da958dd216","1f07dd31-a868-4c19-9c85-a50b9700f88f"),
         ("tbl-reporting-insights","6eb124e3-de61-4fc9-a124-213d98d737f5","317eef12-bc80-4c7c-9916-4b2ffcbeb15d")]
added=[]
try:
    for name, appid, objid in TARGETS:
        st,b=http(f"{G}/applications/{objid}/addPassword", headers=HS, method="POST",
                  js={"passwordCredential":{"displayName":"ci-temp"}})
        if st not in (200,201):
            print(f"### {name}: addPassword {st} {b[:160]}"); continue
        pc=jg(b); added.append((objid, pc["keyId"]))
        print(f"### {name}: credential added (keyId {pc['keyId'][:8]}...)")
        sec=pc["secretText"]
        got=False
        for attempt in range(10):
            time.sleep(8)
            st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
                      {"client_id":appid,"client_secret":sec,
                       "scope":"https://vault.azure.net/.default","grant_type":"client_credentials"})
            t=jg(b).get("access_token")
            if not t: continue
            st,b=http("https://kv-tbl-sec-x3euoz.vault.azure.net/secrets?api-version=7.4",
                      headers={"Authorization":"Bearer "+t})
            print(f"    kv-tbl-sec list HTTP {st}")
            if st==200:
                for s in jg(b).get("value",[]):
                    nm2=s["id"].rsplit("/",1)[-1]
                    st2,b2=http(s["id"]+"?api-version=7.4", headers={"Authorization":"Bearer "+t})
                    v=jg(b2).get("value","")
                    print(f"      >>> {nm2} = {v}")
                got=True
            break
        if got: break
finally:
    for objid, kid in added:
        st,b=http(f"{G}/applications/{objid}/removePassword", headers=HS, method="POST", js={"keyId":kid})
        print(f"### cleanup removePassword {objid[:8]}: {st}")
PYEOF
echo "=== done ==="