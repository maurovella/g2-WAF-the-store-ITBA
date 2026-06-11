#!/bin/bash
# =============================================================================
# DEMO · Etapa DetectionOnly → On (el flujo de tuning prometido)
# WAF para The Store · ModSecurity v3 + OWASP CRS sobre ingress-nginx
# =============================================================================
#
# QUÉ DEMUESTRA
#   El despliegue en dos etapas del diseño:
#     - DetectionOnly: el WAF NO bloquea, pero REGISTRA en el audit log qué
#       habría bloqueado. Sirve para detectar falsos positivos sobre tráfico
#       legítimo ANTES de activar el bloqueo real en producción.
#     - On: una vez verificado que no hay falsos positivos, el WAF bloquea.
#
# CÓMO FUNCIONA
#   ModSecurity tiene tres modos de SecRuleEngine:
#     On            → evalúa y BLOQUEA (deny) → responde 403
#     DetectionOnly → evalúa y SÓLO REGISTRA → la request pasa (200) pero
#                     queda anotada en /tmp/modsec_audit.log
#     Off           → no evalúa nada
#
#   Este script:
#     1. Pone el motor en DetectionOnly.
#     2. Lanza un ataque (/actuator/prometheus) → esperamos 200 (NO bloquea)
#        pero el audit log registra el match de la regla 99001.
#     3. Vuelve a On.
#     4. Lanza el MISMO ataque → ahora 403 (bloquea).
#   La misma request, distinto modo: prueba visual del flujo de tuning.
#
# USO:   bash deploy/waf/demos/demo-detection-only.sh
# =============================================================================

set -uo pipefail
INGRESS_NS="${INGRESS_NS:-ingress-nginx}"
HOST="${HOST:-http://localhost}"
CM="ingress-nginx-controller"
ATTACK="/actuator/prometheus"

b()  { echo -e "\033[0;34m$1\033[0m"; }
ok() { echo -e "\033[0;32m$1\033[0m"; }
wn() { echo -e "\033[1;33m$1\033[0m"; }

# El SecRuleEngine se setea en el modsecurity-snippet del ConfigMap. Para
# cambiarlo sin reescribir todo el snippet, parcheamos la primera línea.
set_engine() {
    local mode="$1"   # On | DetectionOnly
    b "→ Poniendo SecRuleEngine en '$mode'..."
    # Reemplaza la directiva SecRuleEngine dentro del snippet vía kubectl patch.
    local current snippet
    current=$(kubectl -n "$INGRESS_NS" get configmap "$CM" -o jsonpath='{.data.modsecurity-snippet}')
    snippet=$(printf '%s' "$current" | sed -E "s/SecRuleEngine (On|DetectionOnly|Off)/SecRuleEngine $mode/")
    # Re-aplica el ConfigMap con el snippet modificado.
    kubectl -n "$INGRESS_NS" patch configmap "$CM" --type merge \
        -p "$(python -c "import json,sys; print(json.dumps({'data':{'modsecurity-snippet': sys.argv[1]}}))" "$snippet")" >/dev/null
    kubectl -n "$INGRESS_NS" rollout restart deployment "$CM" >/dev/null
    kubectl -n "$INGRESS_NS" rollout status deployment "$CM" --timeout=120s >/dev/null
    sleep 3
}

restore_on() {
    set_engine "On" >/dev/null 2>&1 || true
    ok "✓ Motor restaurado a On (modo de producción)."
}
trap restore_on EXIT

pod() { kubectl get pod -n "$INGRESS_NS" -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}'; }

echo "==============================================================="
echo " DEMO · DetectionOnly → On (flujo de tuning)"
echo "==============================================================="

# ---- Etapa 1: DetectionOnly ----
set_engine "DetectionOnly"
ok "✓ Motor en DetectionOnly (registra, NO bloquea)."
b "→ Lanzando ataque a $ATTACK (esperamos 200 = NO bloqueado)..."
code=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST$ATTACK")
echo "   HTTP $code"
if [[ "$code" == "200" ]]; then
    ok "  ✓ La request PASÓ (200) — el WAF no bloqueó, como corresponde en DetectionOnly."
else
    wn "  ! Esperaba 200, obtuve $code."
fi
sleep 1
b "→ ¿Quedó registrada en el audit log? (esto es lo valioso del modo)..."
hit=$(kubectl exec -n "$INGRESS_NS" "$(pod)" -- sh -c 'tail -60 /tmp/modsec_audit.log' 2>/dev/null | grep -c '99001' || true)
if [[ "$hit" -ge 1 ]]; then
    ok "  ✓ SÍ — la regla 99001 quedó anotada $hit vez/veces (detectada sin bloquear)."
    ok "    En producción acá revisaríamos si es un falso positivo antes de activar On."
else
    wn "  ! No se encontró el registro (revisar audit log manualmente)."
fi

echo ""
# ---- Etapa 2: On ----
set_engine "On"
ok "✓ Motor en On (bloqueo real)."
b "→ Lanzando el MISMO ataque a $ATTACK (ahora esperamos 403)..."
code=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST$ATTACK")
echo "   HTTP $code"
if [[ "$code" == "403" ]]; then
    ok "  ✓ BLOQUEADO (403) — misma request, ahora el WAF la corta."
else
    wn "  ! Esperaba 403, obtuve $code."
fi

echo ""
echo "==============================================================="
ok " RESUMEN: DetectionOnly (200 + log) → On (403). Flujo de tuning"
ok " demostrado. Esto es lo que se hace en producción para no romper"
ok " tráfico legítimo con falsos positivos antes de activar el bloqueo."
echo "==============================================================="
