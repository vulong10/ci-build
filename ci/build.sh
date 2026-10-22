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
echo "### installed package versions"
ls /tmp/x/usr/local/lib/python3.12/site-packages/ 2>/dev/null | grep -iE 'dist-info' | head -30
echo
echo "### jinja2 __version__"
grep -rh '__version__' /tmp/x/usr/local/lib/python3.12/site-packages/jinja2/__init__.py 2>/dev/null
echo
echo "### sandbox.py signature checks (CVE-2024-56326 / 56201 indicators)"
grep -n 'format_map\|is_safe_attribute\|_IdentityFunction\|unsafe\|safe_format' /tmp/x/usr/local/lib/python3.12/site-packages/jinja2/sandbox.py 2>/dev/null | head -30

echo
echo "### live render endpoint probes (through Front Door)"
B=https://tbl-storefront-prod-bhagdnascpfyeyfg.z02.azurefd.net
probe () {
  echo "--- $1"
  curl -sS -o /tmp/r.txt -w "HTTP %{http_code}\n" -X POST "$B/api/v1/reports/render" \
       -H 'Content-Type: application/json' --data-binary "$1" --max-time 25
  head -c 400 /tmp/r.txt; echo
}
probe '{"markdown":"plain text"}'
probe '{"markdown":"{{ 7*7 }}"}'
probe '{"markdown":"{{ company }}"}'
probe '{"markdown":"{{ shipments.__class__ }}"}'
probe '{"markdown":"{{ (shipments|first).items }}"}'
echo "=== done ==="