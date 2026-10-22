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
RG="rg-tbl-platform-prod-sea"; G="https://graph.microsoft.com/v1.0"; q=urllib.parse.quote
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
def oidc(sc):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,"scope":sc,
      "grant_type":"client_credentials","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion":IDT}); return jg(b).get("access_token")
KVT=oidc("https://vault.azure.net/.default"); ARM=oidc("https://management.azure.com/.default")
creds={}
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
for s in jg(b).get("value",[]):
    n=s["id"].rsplit("/",1)[-1]
    st2,b2=http(s["id"]+"?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
    try: creds[n]=json.loads(jg(b2).get("value",""))
    except Exception: pass
def gtok(c):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
      {"client_id":c["appId"],"client_secret":c["clientSecret"],
       "scope":"https://graph.microsoft.com/.default","grant_type":"client_credentials"})
    return jg(b).get("access_token")
HA={"Authorization":"Bearer "+gtok(creds["directory-audit-principal"])}
HS={"Authorization":"Bearer "+gtok(creds["sync-service-principal"])}

print("### managed identities / all SPs in tenant")
st,b=http(f"{G}/servicePrincipals?$select=" + q("id,displayName,appId,servicePrincipalType") + "&$top=999", headers=HA)
sps=jg(b).get("value",[])
print("  total SPs:", len(sps), "HTTP", st)
for s in sps:
    if s.get("servicePrincipalType")=="ManagedIdentity" or s.get("displayName","").lower().startswith(("tbl","id-","mi-")):
        print(f"   {s.get('servicePrincipalType'):18} {s.get('displayName'):34} appId={s.get('appId')} oid={s['id']}")

print("\n### resolve the UAMI referenced by another team's payload")
for t in ("7a85156a-01c4-4e61-8472-40a92107159b","d2cdf247-9319-40cb-8324-5a005ef538da"):
    st,b=http(f"{G}/servicePrincipals?$filter=" + q(f"appId eq '{t}'"), headers=HA)
    v=jg(b).get("value",[])
    print(f"  by appId {t[:8]}: {st} {[x.get('displayName') for x in v]}")
    st,b=http(f"{G}/directoryObjects/{t}", headers=HA)
    d=jg(b)
    print(f"  by objectId {t[:8]}: {st} type={d.get('@odata.type')} name={d.get('displayName')} upn={d.get('userPrincipalName')}")

print("\n### federatedIdentityCredentials on every application")
st,b=http(f"{G}/applications?$select=" + q("id,displayName,appId"), headers=HS)
for a in jg(b).get("value",[]):
    st2,b2=http(f"{G}/applications/{a['id']}/federatedIdentityCredentials", headers=HS)
    fics=jg(b2).get("value",[])
    if fics or st2!=200:
        print(f"  {a['displayName']:26} HTTP {st2}")
        for f in fics:
            print(f"     name={f.get('name')} issuer={f.get('issuer')} subject={f.get('subject')} aud={f.get('audiences')}")
    else:
        print(f"  {a['displayName']:26} (none)")

print("\n### role assignments at RG filtered per managed identity")
for s in sps:
    if s.get("servicePrincipalType")!="ManagedIdentity": continue
    u=(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Authorization/"
       f"roleAssignments?api-version=2022-04-01&$filter=" + q(f"principalId eq '{s['id']}'"))
    st,b=http(u, headers={"Authorization":"Bearer "+ARM})
    v=jg(b).get("value",[])
    if v: print(f"  {s.get('displayName')}: {[x['properties']['roleDefinitionId'].rsplit('/',1)[-1] for x in v]}")
PYEOF
echo "=== done ==="