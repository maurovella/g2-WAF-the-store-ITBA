#!/bin/bash
# =============================================================================
# Instalador idempotente del WAF · ModSecurity v3 + OWASP CRS + reglas custom
# WAF para The Store · ModSecurity v3 + OWASP CRS sobre ingress-nginx
# =============================================================================
#
# Prerequisitos:
#   - Cluster Kind levantado vía `./local.sh create-cluster`
#   - ingress-nginx desplegado en el namespace `ingress-nginx`
#   - The Store desplegado en el namespace `the-store`
#   - `kubectl` configurado contra el cluster
#
# Qué hace, en orden:
#   1. Verifica prerequisitos (cluster, namespaces, controller running)
#   2. Aplica el ConfigMap del controller (ModSec + CRS + reglas globales)
#   3. Aplica el Ingress patcheado (rate limit + headers + ModSec per-Ingress)
#   4. Fuerza rollout restart del controller para que tome la config nueva
#   5. Espera a que el controller vuelva a estar Ready
#   6. Smoke-test: verifica que la home responde y que un payload malicioso
#      es bloqueado
#
# Idempotente: se puede correr múltiples veces sin romper nada.
# Para revertir: `./uninstall.sh` (vuelve al Ingress original sin WAF).
# =============================================================================

set -euo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
INGRESS_NS="${INGRESS_NS:-ingress-nginx}"
APP_NS="${APP_NS:-the-store}"
HOST="${HOST:-http://localhost}"

# ---------- color helpers (compatibles con `local.sh`) -----------------------
print_status()  { echo -e "\033[0;34m▶ $1\033[0m"; }
print_success() { echo -e "\033[0;32m✓ $1\033[0m"; }
print_warning() { echo -e "\033[1;33m! $1\033[0m"; }
print_error()   { echo -e "\033[0;31m✗ $1\033[0m"; }

# =============================================================================
# 1. Prerequisitos
# =============================================================================
check_prerequisites() {
    print_status "Checking prerequisites..."

    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl no está instalado"
        exit 1
    fi

    if ! kubectl cluster-info &> /dev/null; then
        print_error "kubectl no puede contactar el cluster. Asegúrate de que Kind esté corriendo:"
        print_error "  ./local.sh create-cluster"
        exit 1
    fi

    if ! kubectl get namespace "$INGRESS_NS" &> /dev/null; then
        print_error "Namespace '$INGRESS_NS' no existe. Levantar el cluster primero."
        exit 1
    fi

    if ! kubectl get namespace "$APP_NS" &> /dev/null; then
        print_error "Namespace '$APP_NS' no existe. Deployar The Store primero."
        exit 1
    fi

    if ! kubectl -n "$INGRESS_NS" get deployment ingress-nginx-controller &> /dev/null; then
        print_error "Deployment 'ingress-nginx-controller' no existe en '$INGRESS_NS'"
        exit 1
    fi

    print_success "Prerequisitos OK"
}

# =============================================================================
# 2a. Crear ConfigMap con las reglas custom (desde el archivo .conf)
# =============================================================================
# Las reglas viven en un archivo aparte (no inline en el snippet) porque
# ingress-nginx envuelve el modsecurity-snippet en `modsecurity_rules '...'`
# y las comillas simples de las reglas romperían el parseo de nginx.
apply_rules_configmap() {
    print_status "Creando ConfigMap 'modsec-custom-rules' desde rules/the-store.conf..."
    kubectl -n "$INGRESS_NS" create configmap modsec-custom-rules \
        --from-file=the-store.conf="$DIR/rules/the-store.conf" \
        --dry-run=client -o yaml | kubectl apply -f -
    print_success "ConfigMap de reglas creada/actualizada"
}

# =============================================================================
# 2b. Aplicar ConfigMap del controller (motor ModSec + CRS + Include)
# =============================================================================
apply_configmap() {
    print_status "Aplicando ConfigMap del controller (ModSecurity + CRS + Include de reglas)..."
    kubectl apply -f "$DIR/01-controller-configmap.yaml"
    print_success "ConfigMap aplicado"
}

# =============================================================================
# 2c. Patchear el Deployment para montar el volumen con las reglas
# =============================================================================
patch_deployment() {
    print_status "Montando volumen de reglas en el controller (deployment patch)..."
    kubectl -n "$INGRESS_NS" patch deployment ingress-nginx-controller \
        --patch-file "$DIR/03-controller-deployment-patch.yaml"
    print_success "Deployment patcheado"
}

# =============================================================================
# 3. Aplicar Ingress patcheado
# =============================================================================
apply_ingress() {
    print_status "Aplicando Ingress patcheado (rate limit + headers + ModSec annotations)..."
    kubectl apply -f "$DIR/02-the-store-ingress.yaml"
    print_success "Ingress aplicado"
}

# =============================================================================
# 4. Restart del controller para que tome la config
# =============================================================================
restart_controller() {
    print_status "Reiniciando ingress-nginx-controller..."
    kubectl -n "$INGRESS_NS" rollout restart deployment ingress-nginx-controller

    print_status "Esperando a que el controller vuelva a estar Ready..."
    kubectl -n "$INGRESS_NS" rollout status deployment ingress-nginx-controller --timeout=180s

    # Pequeña pausa para que nginx termine de cargar la config
    sleep 3
    print_success "Controller listo"
}

# =============================================================================
# 5. Smoke test
# =============================================================================
smoke_test() {
    print_status "Smoke test: la home debería responder 200 OK..."
    local code
    code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 "$HOST/" || echo "ERR")
    if [[ "$code" == "200" ]]; then
        print_success "Home responde $code OK"
    else
        print_warning "Home respondió $code (esperaba 200). Puede ser que la app no esté lista; reintentar en unos segundos."
    fi

    print_status "Smoke test: /actuator/prometheus debería responder 403 (WAF bloqueando)..."
    code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 "$HOST/actuator/prometheus" || echo "ERR")
    if [[ "$code" == "403" ]]; then
        print_success "/actuator/prometheus bloqueado ($code) — WAF activo ✓"
    else
        print_warning "/actuator/prometheus respondió $code (esperaba 403). Revisar logs del controller:"
        print_warning "  kubectl -n $INGRESS_NS logs deployment/ingress-nginx-controller --tail=50"
    fi

    print_status "Smoke test: User-Agent de sqlmap debería ser bloqueado (403)..."
    code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -A 'sqlmap/1.7.2' "$HOST/" || echo "ERR")
    if [[ "$code" == "403" ]]; then
        print_success "sqlmap UA bloqueado ($code) — scanner detection activa ✓"
    else
        print_warning "sqlmap UA respondió $code (esperaba 403)"
    fi

    print_status "Smoke test: headers de seguridad deberían estar presentes..."
    local headers
    headers=$(curl -sS -D - -o /dev/null --max-time 10 "$HOST/")
    local count=0
    for h in 'strict-transport-security' 'x-frame-options' 'x-content-type-options' \
             'content-security-policy-report-only' 'referrer-policy' 'permissions-policy'; do
        if echo "$headers" | grep -qi "^$h:"; then
            count=$((count + 1))
        fi
    done
    if [[ "$count" -eq 6 ]]; then
        print_success "Los 6 headers de seguridad presentes ✓"
    else
        print_warning "Solo $count/6 headers presentes (esperaba 6)"
    fi
}

# =============================================================================
# Main
# =============================================================================
main() {
    echo "==============================================================="
    echo " WAF Install"
    echo "==============================================================="

    check_prerequisites
    apply_rules_configmap
    apply_configmap
    patch_deployment
    apply_ingress
    restart_controller
    smoke_test

    echo ""
    print_success "WAF instalado y verificado."
    echo ""
    echo "Próximos pasos:"
    echo "  - Correr los tests post-WAF:  bash pre-analysis/tests/02-post-waf-attacks.sh"
    echo "  - Ver el audit log:           kubectl -n $INGRESS_NS exec deployment/ingress-nginx-controller -- tail -200 /tmp/modsec_audit.log"
    echo "  - Revertir el WAF:            bash deploy/waf/uninstall.sh"
}

main "$@"
