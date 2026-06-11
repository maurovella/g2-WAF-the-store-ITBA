#!/bin/bash
# =============================================================================
# Recolector de evidencia post-WAF
# WAF para The Store · ModSecurity v3 + OWASP CRS sobre ingress-nginx
# =============================================================================
#
# Corre los tests post-WAF y guarda toda la evidencia en
# `pre-analysis/evidencias/post-waf/`. Esa carpeta es la fuente de verdad
# para el informe final y la demo.
#
# Genera:
#   resultados-post-waf.txt     ← output del 02-post-waf-attacks.sh
#   curl-headers-home.txt       ← headers de la home (los 6 de seguridad)
#   modsec_audit.log            ← audit log del controller (qué regla disparó cada bloqueo)
#   controller-logs.txt         ← stdout del controller filtrando errores
#   summary.md                  ← resumen ejecutable para el informe
# =============================================================================

set -u
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
REPO_ROOT="$( cd "$DIR/../.." && pwd )"
OUT="$REPO_ROOT/pre-analysis/evidencias/post-waf"
HOST="${HOST:-http://localhost}"
INGRESS_NS="${INGRESS_NS:-ingress-nginx}"

mkdir -p "$OUT"

echo "==============================================================="
echo " Captura de evidencia post-WAF · destino: $OUT"
echo "==============================================================="

# 1. Tests automatizados
echo ""
echo "[1/5] Corriendo 02-post-waf-attacks.sh..."
bash "$DIR/02-post-waf-attacks.sh" 2>&1 | tee "$OUT/resultados-post-waf.txt"
RESULT=$?

# 2. Headers de la home — captura completa de un curl -i
echo ""
echo "[2/5] Capturando headers de la home..."
curl -sS -D - -o /dev/null --max-time 5 "$HOST/" > "$OUT/curl-headers-home.txt" 2>&1
echo "  → $OUT/curl-headers-home.txt"

# 3. Audit log de ModSecurity
echo ""
echo "[3/5] Extrayendo modsec_audit.log del controller..."
if kubectl -n "$INGRESS_NS" exec deployment/ingress-nginx-controller -- test -f /tmp/modsec_audit.log 2>/dev/null; then
    kubectl -n "$INGRESS_NS" exec deployment/ingress-nginx-controller -- tail -500 /tmp/modsec_audit.log > "$OUT/modsec_audit.log" 2>&1
    echo "  → $OUT/modsec_audit.log ($(wc -l < "$OUT/modsec_audit.log") líneas)"
else
    echo "  WARN: /tmp/modsec_audit.log no existe aún (¿se corrieron los ataques?)"
fi

# 4. Logs del controller filtrando errores
echo ""
echo "[4/5] Capturando logs del controller (últimas 200 líneas)..."
kubectl -n "$INGRESS_NS" logs deployment/ingress-nginx-controller --tail=200 > "$OUT/controller-logs.txt" 2>&1
echo "  → $OUT/controller-logs.txt"

# 5. Summary markdown
echo ""
echo "[5/5] Generando resumen..."
cat > "$OUT/summary.md" <<EOF
# Evidencia post-WAF · $(date '+%Y-%m-%d %H:%M:%S')

## Resultado del script de tests

Exit code de \`02-post-waf-attacks.sh\`: **$RESULT**
(0 = todos los tests pasaron · != 0 = al menos uno falló)

Ver \`resultados-post-waf.txt\` para el output completo.

## Headers de la home (los 6 de seguridad esperados)

\`\`\`
$(grep -iE '^(strict-transport|x-frame-options|x-content-type-options|content-security|referrer-policy|permissions-policy)' "$OUT/curl-headers-home.txt" 2>/dev/null || echo "(no se encontraron headers — revisar curl-headers-home.txt)")
\`\`\`

## Reglas ModSec que dispararon

$(grep -oE 'WAF-TS-[0-9]+|id "[0-9]+"' "$OUT/modsec_audit.log" 2>/dev/null | sort | uniq -c | sort -rn | head -20 || echo "(no hay audit log todavía)")

## Cómo leer esta carpeta

| Archivo | Para qué sirve |
|---|---|
| \`resultados-post-waf.txt\` | Output completo del script de tests · cita en el informe final |
| \`curl-headers-home.txt\` | Prueba "vivencial" de que los 6 headers están presentes · screenshot para PPT |
| \`modsec_audit.log\` | Audit log de ModSecurity · prueba que CADA bloqueo lo hizo una regla específica |
| \`controller-logs.txt\` | Logs del nginx · útil si algo no funciona como se espera |
| \`summary.md\` | Este resumen · ejecutivo |

EOF

echo "  → $OUT/summary.md"
echo ""
echo "==============================================================="
echo " Evidencia capturada en: $OUT"
echo "==============================================================="

exit $RESULT
