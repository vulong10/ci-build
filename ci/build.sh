#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, base64, urllib.request, urllib.parse
def http(url, data=None, headers=None, method=None):
    h=dict(headers or {}); body=None
    if isinstance(data, dict):
        body=urllib.parse.urlencode(data).encode(); h.setdefault("Content-Type","application/x-www-form-urlencoded")
    req=urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()
def jg(b):
    try: return json.loads(b)
    except Exception: return {}
def claims(t):
    p=t.split(".")[1]; p+="="*(-len(p)%4); return json.loads(base64.urlsafe_b64decode(p))
TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]; SUB=os.environ["AZURE_SUBSCRIPTION_ID"]
RG="rg-tbl-platform-prod-sea"; REG="crtblplatprodx3euoz.azurecr.io"; G="https://graph.microsoft.com/v1.0"
MI="eeab432e-1bf6-400e-b155-a28ce7cafcdb"; AUTO_OBJ=None
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
def oidc(sc):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,"scope":sc,
      "grant_type":"client_credentials","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion":IDT}); return jg(b).get("access_token")
ARM=oidc("https://management.azure.com/.default"); KVT=oidc("https://vault.azure.net/.default")
H={"Authorization":"Bearer "+ARM}

print("### role assignments for the App Service managed identity")
u=(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Authorization/"
   f"roleAssignments?api-version=2022-04-01&$filter=" + urllib.parse.quote(f"principalId eq '{MI}'"))
st,b=http(u, headers=H)
print("  HTTP", st, "->", b[:400].decode("utf-8","replace"))

print("\n### ACR token scopes actually granted (pull vs push)")
st,b=http(f"https://{REG}/oauth2/exchange",{"grant_type":"access_token","service":REG,"tenant":TEN,"access_token":ARM})
RT=jg(b)["refresh_token"]
for scope in ("repository:tebamoto-reporting-api:pull",
              "repository:tebamoto-reporting-api:pull,push",
              "repository:tebamoto-reporting-api:*",
              "registry:catalog:*"):
    st,b=http(f"https://{REG}/oauth2/token",{"grant_type":"refresh_token","service":REG,"refresh_token":RT,"scope":scope})
    at=jg(b).get("access_token")
    if at:
        c=claims(at)
        print(f"  requested {scope:46} -> granted: {json.dumps(c.get('access'))[:200]}")
    else:
        print(f"  requested {scope:46} -> {st} {b[:120]}")

print("\n### ArmOwner app-role holders (appRoleAssignedTo)")
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/sync-service-principal?api-version=7.4",
          headers={"Authorization":"Bearer "+KVT})
sc=json.loads(jg(b)["value"])
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
  {"client_id":sc["appId"],"client_secret":sc["clientSecret"],
   "scope":"https://graph.microsoft.com/.default","grant_type":"client_credentials"})
HS={"Authorization":"Bearer "+jg(b)["access_token"]}
st,b=http(f"{G}/servicePrincipals?$filter=" + urllib.parse.quote("appId eq '462d1c38-4459-48b8-9333-82e389e59514'"), headers=HS)
sps=jg(b).get("value",[])
if sps:
    spid=sps[0]["id"]; print("  automation SP objectId:", spid)
    st,b=http(f"{G}/servicePrincipals/{spid}/appRoleAssignedTo", headers=HS)
    print("  appRoleAssignedTo:", st)
    for r in jg(b).get("value",[]):
        print(f"    {r.get('principalDisplayName')} ({r.get('principalType')}) principalId={r.get('principalId')}")
    st,b=http(f"{G}/servicePrincipals/{spid}/appRoleAssignments", headers=HS)
    print("  its own appRoleAssignments:", st, [(x.get('resourceDisplayName'),x.get('appRoleId')) for x in jg(b).get('value',[])])
PYEOF
echo "=== done ==="