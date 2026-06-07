#!/bin/bash
# =============================================================================
# DEMO · Rate limit POR IP — aislamiento entre clientes
# TPE Tema 9 · WAF para The Store · Grupo 2 · ITBA 1C 2026
# =============================================================================
#
# QUÉ DEMUESTRA
#   Que el rate limit del Ingress aísla por dirección IP de cliente: un cliente
#   que abusa (cientos de requests) recibe 429, mientras OTRO cliente con IP
#   distinta sigue navegando con 200. No es un límite global que castiga a todos.
#
# EL PROBLEMA QUE RESUELVE (debilidad detectada en la auto-evaluación)
#   En Kind, TODO el tráfico externo llega con la misma IP de origen TCP (el
#   bridge Docker / kube-proxy). El rate limit de nginx se keyea por
#   `$binary_remote_addr`, así que con tráfico real "localhost" no se puede
#   distinguir un cliente de otro: todos caen en el mismo bucket.
#
# CÓMO LO DEMOSTRAMOS HONESTAMENTE
#   El módulo realip de nginx reescribe `$binary_remote_addr` con el valor de
#   X-Forwarded-For CUANDO `use-forwarded-headers: true`. Eso es exactamente lo
#   que hace un balanceador L4 confiable delante del Ingress en producción.
#   Entonces:
#     1. Activamos temporalmente use-forwarded-headers=true (simula tener un
#        L4 LB confiable que setea XFF).
#     2. El "atacante" manda 80 requests concurrentes con XFF=10.10.10.1.
#     3. La "víctima" manda 15 requests con XFF=10.10.10.2.
#     4. Verificamos: atacante recibe 429s, víctima sigue 200 → AISLAMIENTO.
#     5. Restauramos use-forwarded-headers=false (nuestro default SEGURO).
#
# TRADE-OFF DE SEGURIDAD (punto clave para la oral)
#   Para rate-limitar por IP hay que confiar en XFF. Pero confiar en XFF de
#   cualquiera reabre el spoofing (Hallazgo 03). Por eso en el POC el default
#   es use-forwarded-headers=false: en producción se pone =true SOLO cuando hay
#   un L4 LB confiable que sobreescribe el XFF del cliente. Este script muestra
#   las dos caras de esa misma moneda.
#
# USO:   bash deploy/waf/demos/demo-rate-limit-per-ip.sh
# =============================================================================

set -uo pipefail
INGRESS_NS="${INGRESS_NS:-ingress-nginx}"
HOST="${HOST:-http://localhost}"
CM="ingress-nginx-controller"

b()  { echo -e "\033[0;34m$1\033[0m"; }
ok() { echo -e "\033[0;32m$1\033[0m"; }
wn() { echo -e "\033[1;33m$1\033[0m"; }

restore_secure_default() {
    b "→ Restaurando use-forwarded-headers=false (default seguro)..."
    kubectl -n "$INGRESS_NS" patch configmap "$CM" --type merge \
        -p '{"data":{"use-forwarded-headers":"false","compute-full-forwarded-for":"false"}}' >/dev/null
    kubectl -n "$INGRESS_NS" rollout restart deployment "$CM" >/dev/null
    kubectl -n "$INGRESS_NS" rollout status deployment "$CM" --timeout=120s >/dev/null
    ok "✓ Default seguro restaurado (el WAF vuelve a ignorar XFF entrante)."
}
# Garantiza restaurar incluso si el script se interrumpe (Ctrl-C / error).
trap restore_secure_default EXIT

echo "==============================================================="
echo " DEMO · Rate limit POR IP (aislamiento entre clientes)"
echo "==============================================================="

b "→ Paso 1: activar use-forwarded-headers=true (simula L4 LB confiable)..."
kubectl -n "$INGRESS_NS" patch configmap "$CM" --type merge \
    -p '{"data":{"use-forwarded-headers":"true","compute-full-forwarded-for":"true"}}' >/dev/null
kubectl -n "$INGRESS_NS" rollout restart deployment "$CM" >/dev/null
kubectl -n "$INGRESS_NS" rollout status deployment "$CM" --timeout=120s >/dev/null
sleep 3
ok "✓ realip activo: ahora nginx keyea el rate limit por el XFF recibido."

b "→ Paso 2: ATACANTE (IP 10.10.10.1) lanza 200 requests concurrentes..."
atk=$(seq 1 200 | xargs -P 80 -I{} curl -sS -o /dev/null -w "%{http_code}\n" \
        --max-time 10 -H "X-Forwarded-For: 10.10.10.1" "$HOST/" 2>/dev/null)
atk_200=$(printf '%s\n' "$atk" | grep -c '^200$' || true)
atk_429=$(printf '%s\n' "$atk" | grep -cE '^(429|503)$' || true)
echo "   atacante 10.10.10.1 → $atk_200 OK · $atk_429 throttled (429)"

b "→ Paso 3: VÍCTIMA (IP 10.10.10.2) navega normal, 15 requests..."
vic=""
for i in $(seq 1 15); do
    vic="$vic$(curl -sS -o /dev/null -w "%{http_code} " --max-time 10 \
        -H "X-Forwarded-For: 10.10.10.2" "$HOST/" 2>/dev/null)"
    sleep 0.15
done
vic_200=$(printf '%s' "$vic" | tr ' ' '\n' | grep -c '^200$' || true)
vic_429=$(printf '%s' "$vic" | tr ' ' '\n' | grep -cE '^(429|503)$' || true)
echo "   víctima  10.10.10.2 → $vic_200 OK · $vic_429 throttled (429)"

echo ""
echo "==============================================================="
echo " RESULTADO"
echo "==============================================================="
echo "   Atacante (10.10.10.1): $atk_200 OK / $atk_429 throttled"
echo "   Víctima  (10.10.10.2): $vic_200 OK / $vic_429 throttled"
echo ""
# La prueba CLAVE del aislamiento es que la víctima NO se vea afectada por el
# abuso del atacante (bucket separado). El throttling del atacante es la prueba
# secundaria de que el límite efectivamente actúa.
if [[ "$vic_429" -eq 0 && "$vic_200" -ge 10 && "$atk_429" -ge 1 ]]; then
    ok "✓ AISLAMIENTO POR IP DEMOSTRADO:"
    ok "  el abusador (10.10.10.1) fue throttleado ($atk_429 × 429) mientras la"
    ok "  víctima (10.10.10.2) navegó SIN UNA SOLA traba ($vic_200/15 OK)."
    ok "  → El rate limit NO es global: cada IP tiene su propio bucket."
else
    wn "! Resultado no concluyente (ver números arriba). Reintentar."
fi
echo ""
wn "NOTA DE SEGURIDAD (decir en la oral):"
echo "  Esta demo CONFÍA en X-Forwarded-For, lo que solo es seguro detrás de un"
echo "  balanceador L4 confiable. Por eso el default del POC es"
echo "  use-forwarded-headers=false (cierra el spoofing del Hallazgo 03). El"
echo "  script restaura ese default seguro al terminar (trap EXIT)."
