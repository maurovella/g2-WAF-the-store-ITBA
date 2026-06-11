#!/bin/bash
# =============================================================================
# Post-WAF security assessment · The Store (TPE WAF · ITBA · 1C 2026)
# =============================================================================
# Espejo de `01-pre-waf-attacks.sh` con las assertions invertidas:
#
#   - Lo que antes era 200 OK (vulnerable) ahora debe ser 403/429 (bloqueado).
#   - Los 6 headers de seguridad deben estar presentes.
#
# Cada test cuenta como PASS si su outcome coincide con lo esperado post-WAF
# (típicamente 403 Forbidden). El script termina con exit-code != 0 si algún
# test falla, así sirve como gate de CI.
#
# Uso:
#   chmod +x 02-post-waf-attacks.sh
#   ./02-post-waf-attacks.sh 2>&1 | tee resultados-post-waf.txt
# =============================================================================

set -u
HOST="${HOST:-http://localhost}"

PASS="\033[0;32mPASS\033[0m"  # WAF bloqueó como se esperaba → bueno
FAIL="\033[0;31mFAIL\033[0m"  # WAF no bloqueó → malo
WARN="\033[1;33mWARN\033[0m"
INFO="\033[0;34mINFO\033[0m"

TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

separator() { echo ""; printf '═%.0s' {1..78}; echo ""; }
header()    { separator; echo "▶ $*"; separator; }

# expect_blocked <name> <actual_code>
# Marca PASS si el código es 403, 406, 429 o 451 (bloqueos del WAF)
expect_blocked() {
    local name="$1"
    local code="$2"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    if [[ "$code" =~ ^(403|406|429|451)$ ]]; then
        echo -e "  [$PASS] $name: HTTP $code (WAF bloqueó como se esperaba)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  [$FAIL] $name: HTTP $code (esperaba 403/429 — el WAF NO bloqueó)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# expect_ok <name> <actual_code>
# Marca PASS si el código es 200/302 — para verificar que la app sigue accesible
expect_ok() {
    local name="$1"
    local code="$2"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    if [[ "$code" =~ ^(200|301|302|303)$ ]]; then
        echo -e "  [$PASS] $name: HTTP $code (tráfico legítimo OK)"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  [$FAIL] $name: HTTP $code (la app debería responder 200)"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# -----------------------------------------------------------------------------
# Recon previo
# -----------------------------------------------------------------------------
header "Recon · headers de la home (post-WAF: deberían estar los 6 de seguridad)"
echo "Response headers:"
curl -sS -D - -o /dev/null --max-time 5 "$HOST/" | grep -iE '^(server|x-powered|strict-transport|x-frame|x-content|content-security|referrer|permissions)' || echo "  (sin headers)"

# -----------------------------------------------------------------------------
# H0 · Tráfico legítimo (sanity check)
# -----------------------------------------------------------------------------
header "H0 · La home sigue accesible (NO debería ser bloqueada por el WAF)"
code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 "$HOST/")
expect_ok "GET /" "$code"

code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 "$HOST/actuator/health")
expect_ok "GET /actuator/health (whitelisted para K8s)" "$code"

# -----------------------------------------------------------------------------
# H1 · SSRF / Path Traversal vía /proxy/**  (esperado: BLOQUEADO)
# -----------------------------------------------------------------------------
header "H1 · Path traversal vía /proxy/* (regla custom 99002)"
# --path-as-is: evita que curl normalice el `../` del lado cliente; así el
# `..` literal llega al WAF y dispara la regla 99002 (sin esto, curl colapsa
# el path y manda /debug/pprof, que da 404 por inexistente, no 403).
code=$(curl -sS --path-as-is -o /dev/null -w "%{http_code}" "$HOST/proxy/catalog/../../debug/pprof/")
expect_blocked "H1.a · /proxy/catalog/../../debug/pprof/ (literal ..)" "$code"

code=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST/proxy/carts/actuator/health")
expect_blocked "H1.b · /proxy/carts/actuator/health (regla 99003)" "$code"

code=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST/proxy/orders/%2e%2e%2f%2e%2e%2factuator%2finfo")
expect_blocked "H1.c · path traversal URL-encoded" "$code"

code=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST/proxy/catalog/../../actuator/prometheus")
expect_blocked "H1.d · /proxy/catalog/../../actuator/prometheus" "$code"

# H1.e/f · /proxy/* SIN cookie de sesión válida (reglas 99004/99005).
# La pre-entrega comprometió denegar /proxy/* "que no traiga header de sesión
# válido". El front nunca llama /proxy/*, así que esto sólo corta el acceso
# directo por curl/scanner.
code=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST/proxy/carts/test")
expect_blocked "H1.e · /proxy/carts/test SIN cookie de sesión (regla 99005)" "$code"

code=$(curl -sS -o /dev/null -w "%{http_code}" -H 'Cookie: SESSIONID=invalida' "$HOST/proxy/carts/test")
expect_blocked "H1.f · /proxy/carts/test con SESSIONID mal formada (regla 99004)" "$code"

# H1.g · MISMO request CON una cookie SESSIONID con formato UUID válido debe
# pasar (200): demuestra que no es un bloqueo ciego de /proxy/*, sino que
# discrimina por sesión — como pidió la pre-entrega.
code=$(curl -sS -o /dev/null -w "%{http_code}" -H 'Cookie: SESSIONID=8d085683-1d51-4459-a137-a746a17ce087' "$HOST/proxy/carts/test")
expect_ok "H1.g · /proxy/carts/test con SESSIONID UUID válida (tráfico legítimo)" "$code"

# -----------------------------------------------------------------------------
# H2 · Inyecciones en checkout  (esperado: BLOQUEADO por CRS)
# -----------------------------------------------------------------------------
header "H2 · Inyecciones (CRS 941xxx XSS / 942xxx SQLi)"
code=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$HOST/checkout" \
  --data-urlencode "firstName=<script>alert(1)</script>" \
  --data-urlencode "lastName=Doe" --data-urlencode "email=a@b.com" \
  --data-urlencode "address1=100 Main" --data-urlencode "city=Anytown" \
  --data-urlencode "state=CA" --data-urlencode "zipCode=11111")
expect_blocked "H2.a · XSS en firstName" "$code"

code=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "$HOST/checkout" \
  --data-urlencode "firstName=Robert'); DROP TABLE addresses;--" \
  --data-urlencode "lastName=Doe" --data-urlencode "email=a@b.com" \
  --data-urlencode "address1=100 Main" --data-urlencode "city=A" \
  --data-urlencode "state=CA" --data-urlencode "zipCode=11111")
expect_blocked "H2.b · SQLi en firstName" "$code"

# -----------------------------------------------------------------------------
# H4 · Spring Actuator (regla custom 99001 — esperado: BLOQUEADO)
# -----------------------------------------------------------------------------
header "H4 · Spring Actuator expuesto (regla custom 99001)"
code=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST/actuator/info")
expect_blocked "H4.a · /actuator/info" "$code"

# H4.a2 · el ÍNDICE /actuator (sin sufijo) lista en HAL todos los endpoints
# actuator → mapa de reconocimiento. La regla 99001 ampliada también lo cubre.
code=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST/actuator")
expect_blocked "H4.a2 · /actuator (índice HAL)" "$code"

# H4.b: /actuator/health SÍ debe responder 200 (lo necesita el liveness probe)
code=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST/actuator/health")
expect_ok "H4.b · /actuator/health (whitelisted)" "$code"

code=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST/actuator/metrics")
expect_blocked "H4.c · /actuator/metrics" "$code"

code=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST/actuator/prometheus")
expect_blocked "H4.d · /actuator/prometheus (Hallazgo estrella)" "$code"

code=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST/actuator/env")
expect_blocked "H4.e · /actuator/env" "$code"

# -----------------------------------------------------------------------------
# H6 · Scanner detection + rate limit (reglas 99010 + nginx limit_req)
# -----------------------------------------------------------------------------
header "H6 · Scanner detection (regla custom 99010)"
code=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST/" -A 'Mozilla/5.00 (Nikto/2.5.0)')
expect_blocked "H6.a · User-Agent Nikto" "$code"

code=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST/" -A 'sqlmap/1.7.2#stable (https://sqlmap.org)')
expect_blocked "H6.b · User-Agent sqlmap" "$code"

code=$(curl -sS -o /dev/null -w "%{http_code}" "$HOST/" -A 'Nuclei - Open-source project (github.com/projectdiscovery/nuclei)')
expect_blocked "H6.c · User-Agent nuclei" "$code"

header "H6 · Rate limit (nginx limit_req · 10 rps + burst·3)"
echo "  Lanzando 100 requests CONCURRENTES a / (xargs -P 50)..."
# Paralelismo real: 50 workers concurrentes. Un loop secuencial NO dispara el
# rate limit porque cada curl tarda y los 100 se reparten en >3s (bajo 10 rps).
# Con concurrencia real, nginx limit_req agota el burst (10·3=30) y throttlea
# el resto con 429.
rl_out=$(seq 1 100 | xargs -P 50 -I{} curl -sS -o /dev/null -w "%{http_code}\n" --max-time 10 "$HOST/" 2>/dev/null)
ok_200=$(printf '%s\n' "$rl_out" | grep -c '^200$' || true)
throttled=$(printf '%s\n' "$rl_out" | grep -cE '^(429|503)$' || true)
echo "  → $ok_200/100 con 200 OK · $throttled/100 throttleados (429/503)"
TESTS_TOTAL=$((TESTS_TOTAL + 1))
if [[ "$throttled" -ge 10 ]]; then
    echo -e "  [$PASS] Rate limit activo ($throttled requests bloqueados)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  [$FAIL] Rate limit no parece estar activo (solo $throttled requests bloqueados de 100)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# -----------------------------------------------------------------------------
# H6 · Headers de seguridad (6 esperados)
# -----------------------------------------------------------------------------
header "H6 · 6 headers de seguridad (más-set_headers vía annotation)"
headers=$(curl -sS -D - -o /dev/null --max-time 5 "$HOST/")
# Lista plana "header:nombre-legible" (sin arrays asociativos: el bash 3.2
# default de macOS no soporta `declare -A` y rompería con `set -u`).
expected_headers="
strict-transport-security:HSTS
x-frame-options:X-Frame-Options
x-content-type-options:X-Content-Type-Options
content-security-policy-report-only:CSP-Report-Only
referrer-policy:Referrer-Policy
permissions-policy:Permissions-Policy
"
present=0
for entry in $expected_headers; do
    key="${entry%%:*}"
    name="${entry#*:}"
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    if echo "$headers" | grep -qi "^$key:"; then
        echo -e "  [$PASS] $name presente"
        present=$((present + 1))
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  [$FAIL] $name ausente"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
done
echo "  → $present/6 headers de seguridad presentes"

# -----------------------------------------------------------------------------
# Resumen
# -----------------------------------------------------------------------------
separator
echo "RESUMEN · TESTS POST-WAF"
echo "  Pasaron:  $TESTS_PASSED / $TESTS_TOTAL"
echo "  Fallaron: $TESTS_FAILED / $TESTS_TOTAL"
separator

if [[ "$TESTS_FAILED" -eq 0 ]]; then
    echo -e "  [$PASS] Todos los tests post-WAF pasaron. El WAF cumple con la pre-entrega."
    exit 0
else
    echo -e "  [$FAIL] $TESTS_FAILED tests fallaron. Revisar logs del controller:"
    echo "    kubectl -n ingress-nginx logs deployment/ingress-nginx-controller --tail=100"
    echo "    kubectl -n ingress-nginx exec deployment/ingress-nginx-controller -- tail -200 /tmp/modsec_audit.log"
    exit 1
fi
