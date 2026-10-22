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
        with urllib.request.urlopen(req, timeout=30) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()
def jg(b):
    try: return json.loads(b)
    except Exception: return {}
TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]; SUB=os.environ["AZURE_SUBSCRIPTION_ID"]
G="https://graph.microsoft.com/v1.0"; M="https://management.azure.com"; q=urllib.parse.quote
UAMI_APPID="7a85156a-01c4-4e61-8472-40a92107159b"
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
def oidc(sc):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,"scope":sc,
      "grant_type":"client_credentials","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion":IDT}); return jg(b).get("access_token")
ARM=oidc("https://management.azure.com/.default"); KVT=oidc("https://vault.azure.net/.default")
H={"Authorization":"Bearer "+ARM}
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/directory-audit-principal?api-version=7.4",
          headers={"Authorization":"Bearer "+KVT})
c=json.loads(jg(b)["value"])
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
  {"client_id":c["appId"],"client_secret":c["clientSecret"],
   "scope":"https://graph.microsoft.com/.default","grant_type":"client_credentials"})
HA={"Authorization":"Bearer "+jg(b)["access_token"]}

st,b=http(f"{G}/servicePrincipals?$filter=" + q(f"appId eq '{UAMI_APPID}'") +
          "&$select=" + q("id,displayName,appId,servicePrincipalType,alternativeNames"), headers=HA)
sp=(jg(b).get("value") or [{}])[0]
print("### UAMI service principal")
print("  ", json.dumps(sp, ensure_ascii=False)[:700])
PID=sp.get("id")

print("\n### ARM: list user-assigned identities in subscription")
st,b=http(f"{M}/subscriptions/{SUB}/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31", headers=H)
print("  HTTP", st, b[:600].decode("utf-8","replace"))

print("\n### ARM: list resource groups")
st,b=http(f"{M}/subscriptions/{SUB}/resourcegroups?api-version=2021-04-01", headers=H)
print("  HTTP", st, [g["name"] for g in jg(b).get("value",[])])

if PID:
    print("\n### role assignments for the UAMI principal")
    for scope in (f"/subscriptions/{SUB}",
                  f"/subscriptions/{SUB}/resourceGroups/rg-tbl-platform-prod-sea",
                  f"/subscriptions/{SUB}/resourceGroups/rg-tbl-platform-prod-sea/providers/Microsoft.KeyVault/vaults/kv-tbl-sec-x3euoz"):
        st,b=http(f"{M}{scope}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=" +
                  q(f"principalId eq '{PID}'"), headers=H)
        v=jg(b).get("value",[])
        print(f"  {scope[-60:]}: {st} -> " +
              str([(x['properties']['roleDefinitionId'].rsplit('/',1)[-1], x['properties']['scope'].rsplit('/',1)[-1]) for x in v]))

print("\n### what can WE do on the identity RG / UAMI? (effective permissions)")
for scope in (f"/subscriptions/{SUB}/resourceGroups/rg-tbl-platform-prod-sea",):
    st,b=http(f"{M}{scope}/providers/Microsoft.Authorization/permissions?api-version=2022-04-01", headers=H)
    for p in jg(b).get("value",[]):
        print("  actions:", p.get("actions"), "notActions:", p.get("notActions"))
PYEOF
echo "=== done ==="