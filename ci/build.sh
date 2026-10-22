#!/usr/bin/env bash
set -uo pipefail
IDT=$(curl -sS -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
      "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["value"])')
az login --service-principal -u "$AZURE_CLIENT_ID" --tenant "$AZURE_TENANT_ID" --federated-token "$IDT" -o none 2>&1 | head -2
az acr login -n crtblplatprodx3euoz 2>&1 | head -2
IMG="crtblplatprodx3euoz.azurecr.io/tebamoto-reporting-api:latest"
docker pull -q "$IMG" >/dev/null 2>&1
CT=$(docker create "$IMG"); rm -rf /tmp/x; mkdir -p /tmp/x
docker export "$CT" | tar -xf - -C /tmp/x 2>/dev/null; docker rm "$CT" >/dev/null
echo "######## FULL app.py (from safe_eval onward)"
awk '/def safe_eval/,0' /tmp/x/app/app.py
echo
echo "######## requirements.txt"
cat /tmp/x/app/requirements.txt
echo
echo "######## catalog-api app"
IMG2="crtblplatprodx3euoz.azurecr.io/catalog-api:latest"
docker pull -q "$IMG2" >/dev/null 2>&1
CT2=$(docker create "$IMG2"); rm -rf /tmp/y; mkdir -p /tmp/y
docker export "$CT2" | tar -xf - -C /tmp/y 2>/dev/null; docker rm "$CT2" >/dev/null
find /tmp/y -maxdepth 3 -name '*.py' -not -path '*/site-packages/*' | head -5
head -c 6000 /tmp/y/app/app.py 2>/dev/null
echo "=== done ==="