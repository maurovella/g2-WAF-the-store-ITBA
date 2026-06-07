#!/bin/bash
# =============================================================================
# DEMO · Cobertura del WAF: norte-sur (protegido) vs este-oeste (NO protegido)
# TPE Tema 9 · WAF para The Store · Grupo 2 · ITBA 1C 2026
# =============================================================================
#
# QUÉ DEMUESTRA (concepto de redes clave para la oral)
#   El WAF se inserta en el Ingress, que es el único punto de entrada del
#   tráfico NORTE-SUR (Internet → cluster). NO está en el camino del tráfico
#   ESTE-OESTE (pod → pod dentro del cluster). Por lo tanto:
#
#     - Un atacante DESDE AFUERA (vía http://localhost, atravesando el Ingress)
#       es bloqueado por el WAF.
#     - Un atacante que YA comprometió un pod puede hablarle directo a los
#       backends por su ClusterIP (red 10.96.0.0/12) sin pasar por el WAF.
#
#   Esto NO es un bug: es el alcance declarado en la pre-entrega ("no reemplaza
#   autenticación entre microservicios"). El control complementario para
#   este-oeste serían NetworkPolicies (capa 3/4) o un service mesh con mTLS.
#
# MAPA DE RED (para narrar en la oral)
#   Norte-sur:  Host 127.0.0.1:80 → Ingress (WAF aquí) → Service ui → pod
#   Este-oeste: pod → Service ClusterIP 10.96.0.0/12 → pod  (NUNCA toca el WAF)
#
# USO:   bash deploy/waf/demos/demo-north-south-vs-east-west.sh
# =============================================================================

set -uo pipefail
APP_NS="${APP_NS:-the-store}"
HOST="${HOST:-http://localhost}"

b()  { echo -e "\033[0;34m$1\033[0m"; }
ok() { echo -e "\033[0;32m$1\033[0m"; }
wn() { echo -e "\033[1;33m$1\033[0m"; }

echo "==============================================================="
echo " DEMO · Norte-Sur (WAF protege) vs Este-Oeste (WAF NO ve)"
echo "==============================================================="

# -----------------------------------------------------------------------------
# 1) NORTE-SUR: desde afuera, atravesando el Ingress (donde vive el WAF)
# -----------------------------------------------------------------------------
b "→ [NORTE-SUR] Atacante externo vía Ingress (http://localhost):"
ns1=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 8 "$HOST/actuator/prometheus")
echo "   GET /actuator/prometheus           → HTTP $ns1"
ns2=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 8 "$HOST/proxy/carts/actuator/health")
echo "   GET /proxy/carts/actuator/health   → HTTP $ns2"
if [[ "$ns1" == "403" && "$ns2" == "403" ]]; then
    ok "   ✓ El WAF BLOQUEA (403) el tráfico norte-sur malicioso."
else
    wn "   ! Esperaba 403/403, obtuve $ns1/$ns2."
fi

echo ""
# -----------------------------------------------------------------------------
# 2) ESTE-OESTE: desde un pod comprometido, directo al ClusterIP del backend
# -----------------------------------------------------------------------------
b "→ [ESTE-OESTE] Atacante dentro del cluster, directo al ClusterIP de carts:"
b "   (levantando pod efímero con curl en el namespace $APP_NS...)"
ew=$(kubectl run ew-attacker --rm -i --restart=Never --image=curlimages/curl:8.10.1 \
        -n "$APP_NS" --command -- sh -c '
            a=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 8 http://carts/actuator/health);
            b=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 8 http://carts/actuator/prometheus);
            echo "RESULT health=$a prometheus=$b"
        ' 2>/dev/null | grep "^RESULT")
ew_health=$(echo "$ew" | sed -E 's/.*health=([0-9]+).*/\1/')
ew_prom=$(echo "$ew" | sed -E 's/.*prometheus=([0-9]+).*/\1/')
echo "   GET http://carts/actuator/health      → HTTP ${ew_health:-ERR}"
echo "   GET http://carts/actuator/prometheus  → HTTP ${ew_prom:-ERR}"
if [[ "$ew_health" == "200" ]]; then
    wn "   ⚠ El backend responde DIRECTO (200) — el WAF NO está en este camino."
else
    echo "   (carts respondió ${ew_health:-ERR}; el punto es que NO hay 403 del WAF)"
fi

echo ""
echo "==============================================================="
ok " CONCLUSIÓN"
echo "   - Norte-sur (vía Ingress): WAF activo → 403. Perímetro protegido."
echo "   - Este-oeste (pod→ClusterIP 10.96.0.0/12): el WAF NO intercepta."
echo ""
echo "   Es el alcance declarado en la pre-entrega: el WAF es un control"
echo "   PERIMETRAL (capa 7, norte-sur). Proteger el tráfico este-oeste"
echo "   requiere NetworkPolicies (capa 3/4) o un service mesh con mTLS,"
echo "   que quedaron explícitamente fuera del alcance del POC."
echo "==============================================================="
