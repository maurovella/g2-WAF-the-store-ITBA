#!/bin/bash
# =============================================================================
# Revert del WAF · vuelve al estado pre-WAF
# WAF para The Store · ModSecurity v3 + OWASP CRS sobre ingress-nginx
# =============================================================================
#
# Qué hace:
#   1. Restaura el ConfigMap del controller a sus valores default
#      (sin ModSecurity, sin CRS, sin reglas custom)
#   2. Restaura el Ingress original (`dist/kubernetes.yaml`) sin annotations
#      de rate limit / headers / ModSec
#   3. Reinicia el controller para que limpie la config nginx
#
# Útil para reproducir el escenario pre-WAF y comparar antes/después.
# =============================================================================

set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
REPO_ROOT="$( cd "$DIR/../.." && pwd )"
INGRESS_NS="${INGRESS_NS:-ingress-nginx}"
APP_NS="${APP_NS:-the-store}"

print_status()  { echo -e "\033[0;34m▶ $1\033[0m"; }
print_success() { echo -e "\033[0;32m✓ $1\033[0m"; }
print_warning() { echo -e "\033[1;33m! $1\033[0m"; }

print_status "Borrando ConfigMap del WAF y restaurando default..."
kubectl -n "$INGRESS_NS" delete configmap ingress-nginx-controller --ignore-not-found
kubectl -n "$INGRESS_NS" create configmap ingress-nginx-controller \
  --from-literal=allow-snippet-annotations=false \
  --dry-run=client -o yaml | kubectl apply -f -

print_status "Restaurando Ingress original sin annotations de WAF..."
# Re-aplicar el manifest base de The Store (que tiene el Ingress original)
kubectl apply -n "$APP_NS" -f "$REPO_ROOT/dist/kubernetes.yaml"

print_status "Reiniciando ingress-nginx-controller..."
kubectl -n "$INGRESS_NS" rollout restart deployment ingress-nginx-controller
kubectl -n "$INGRESS_NS" rollout status deployment ingress-nginx-controller --timeout=180s

print_success "WAF revertido. Estado pre-WAF restaurado."
echo ""
echo "Para verificar:"
echo "  curl -i http://localhost/actuator/prometheus   # debería responder 200 OK (no más 403)"
echo "  bash pre-analysis/tests/01-pre-waf-attacks.sh  # debería tener mayoría PASS (=vulnerable)"
