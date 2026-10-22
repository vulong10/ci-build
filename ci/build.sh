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
M="https://management.azure.com"; RG2="rg-tbl-reporting-prod-eus"; SITE="app-tbl-reporting-prod"
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,
  "scope":"https://vault.azure.net/.default","grant_type":"client_credentials",
  "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":IDT})
KVT=jg(b)["access_token"]
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/reporting-service-principal?api-version=7.4",
          headers={"Authorization":"Bearer "+KVT})
c=json.loads(jg(b)["value"])
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
  {"client_id":c["appId"],"client_secret":c["clientSecret"],
   "scope":"https://management.azure.com/.default","grant_type":"client_credentials"})
H={"Authorization":"Bearer "+jg(b)["access_token"]}
BASE=f"{M}/subscriptions/{SUB}/resourceGroups/{RG2}/providers/Microsoft.Web/sites/{SITE}"
st,b=http(BASE+"?api-version=2022-03-01", headers=H)
d=jg(b).get("properties",{})
sc=d.get("siteConfig",{})
print("### site runtime")
for k in ("linuxFxVersion","windowsFxVersion","appCommandLine","pythonVersion","numberOfWorkers"):
    print(f"   {k}: {sc.get(k)}")
print("   state:", d.get("state"), "| httpsOnly:", d.get("httpsOnly"))
print("   possibleOutboundIps:", str(d.get("possibleOutboundIpAddresses"))[:120])
print("\n### full siteConfig keys:", list(sc.keys())[:40])
print("\n### appsettings (reporting-service)")
st,b=http(BASE+"/config/appsettings/list?api-version=2022-03-01", data=b"", headers=H, method="POST")
print("   ", st, json.dumps(jg(b).get("properties",{}))[:600])
print("\n### site source control / deployments")
for p in ("/sourcecontrols/web","/deployments","/config/metadata/list"):
    meth="POST" if p.endswith("/list") else "GET"
    if meth=="POST": st,b=http(BASE+p+"?api-version=2022-03-01", data=b"", headers=H, method="POST")
    else: st,b=http(BASE+p+"?api-version=2022-03-01", headers=H)
    print(f"   {p}: {st} {b[:400].decode('utf-8','replace')}")
PYEOF

echo
echo "### live app, repeated probes (phase machine?)"
B=https://app-tbl-reporting-prod.azurewebsites.net
for i in 1 2 3; do
  echo "-- try $i"; curl -sS --max-time 25 "$B/" | head -c 700; echo
done
echo "-- with X-IDENTITY-HEADER"
curl -sS --max-time 25 -H "X-IDENTITY-HEADER: f0dd3c58-9b64-f90c-ac8a-07ae2390d956" "$B/" | head -c 700; echo
echo "-- POST /"
curl -sS --max-time 25 -X POST "$B/" -H 'Content-Type: application/json' -d '{}' | head -c 700; echo
echo "=== done ==="