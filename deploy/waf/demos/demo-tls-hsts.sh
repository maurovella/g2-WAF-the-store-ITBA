#!/bin/bash
# =============================================================================
# DEMO · TLS en el Ingress → HSTS deja de ser decorativo
# WAF para The Store · ModSecurity v3 + OWASP CRS sobre ingress-nginx
# =============================================================================
#
# QUÉ DEMUESTRA (ataca la debilidad "HSTS sobre HTTP es inerte")
#   En el POC base el tráfico es HTTP puro, así que el header HSTS que servimos
#   es IGNORADO por los navegadores (RFC 6797 §7.2: un HSTS recibido sobre HTTP
#   no se aplica). Acá habilitamos terminación TLS en el Ingress con un
#   certificado self-signed para localhost y mostramos que:
#     1. https://localhost/ responde 200 y el header HSTS AHORA tiene sentido.
#     2. http://localhost/ redirige a https (ssl-redirect del Ingress).
#   Es la terminación TLS "en el Ingress" del diseño.
#
# REQUISITOS: openssl, kubectl. El cluster Kind mapea el puerto 443 al host.
#
# USO:   bash deploy/waf/demos/demo-tls-hsts.sh
#        El script revierte TLS al terminar (deja el POC como estaba, en HTTP).
# =============================================================================

set -uo pipefail
APP_NS="${APP_NS:-the-store}"
INGRESS_NS="${INGRESS_NS:-ingress-nginx}"
SECRET="the-store-tls"
# Dir LOCAL relativo (no /tmp): evita que Git-Bash/MSYS traduzca la ruta cuando
# se la pasamos a kubectl (binario Windows), que es lo que rompía la carga del
# cert. Se borra al final.
CERTDIR="./.tls-demo-tmp"
mkdir -p "$CERTDIR"

b()  { echo -e "\033[0;34m$1\033[0m"; }
ok() { echo -e "\033[0;32m$1\033[0m"; }
wn() { echo -e "\033[1;33m$1\033[0m"; }

revert() {
    b "→ Revirtiendo: quitando TLS del Ingress y borrando el secret..."
    # Reaplica el Ingress original Y remueve explícitamente spec.tls + las
    # anotaciones de ssl-redirect. (kubectl apply NO borra campos agregados por
    # `patch` porque no están en su last-applied-config; hay que removerlos a mano.)
    kubectl apply -f "$(dirname "$0")/../02-the-store-ingress.yaml" >/dev/null 2>&1 || true
    kubectl -n "$APP_NS" patch ingress ui --type=json \
        -p '[{"op":"remove","path":"/spec/tls"}]' >/dev/null 2>&1 || true
    kubectl -n "$APP_NS" annotate ingress ui \
        nginx.ingress.kubernetes.io/ssl-redirect- \
        nginx.ingress.kubernetes.io/force-ssl-redirect- >/dev/null 2>&1 || true
    kubectl -n "$APP_NS" delete secret "$SECRET" >/dev/null 2>&1 || true
    rm -rf "$CERTDIR"
    sleep 4
    ok "✓ POC restaurado a HTTP (estado base)."
}
trap revert EXIT

echo "==============================================================="
echo " DEMO · TLS en el Ingress → HSTS con sentido"
echo "==============================================================="

b "→ Paso 1: generar certificado self-signed para CN=localhost..."
# MSYS_NO_PATHCONV=1: evita que Git-Bash convierta el "/CN=..." del -subj en
# una ruta Windows (rompía el parseo del subject y no generaba el .crt).
MSYS_NO_PATHCONV=1 openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout "$CERTDIR/tls.key" -out "$CERTDIR/tls.crt" \
    -subj "/CN=localhost/O=The Store" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
if [[ ! -s "$CERTDIR/tls.crt" ]]; then
    wn "! No se pudo generar el certificado (revisar openssl). Abortando."; exit 1
fi
ok "✓ Cert generado (CN=localhost, SAN localhost/127.0.0.1)."

b "→ Paso 2: crear el Secret TLS en el namespace $APP_NS..."
MSYS_NO_PATHCONV=1 kubectl -n "$APP_NS" create secret tls "$SECRET" \
    --cert="$CERTDIR/tls.crt" --key="$CERTDIR/tls.key" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
ok "✓ Secret '$SECRET' creado."

b "→ Paso 3: parchear el Ingress para terminar TLS + forzar HTTPS..."
# Agrega spec.tls y la anotación de redirect. El resto del Ingress (WAF, rate
# limit, headers) se mantiene.
kubectl -n "$APP_NS" patch ingress ui --type merge -p '{
  "metadata":{"annotations":{"nginx.ingress.kubernetes.io/ssl-redirect":"true","nginx.ingress.kubernetes.io/force-ssl-redirect":"true"}},
  "spec":{"tls":[{"hosts":["localhost"],"secretName":"'"$SECRET"'"}]}
}' >/dev/null
sleep 4
ok "✓ Ingress con TLS. Esperando reload del controller..."
sleep 3

echo ""
b "→ Paso 4: probar HTTPS (HSTS ahora SÍ aplica)..."
code_https=$(curl -sSk -o /dev/null -w "%{http_code}" --max-time 10 "https://localhost/")
echo "   GET https://localhost/  → HTTP $code_https"
echo "   Header HSTS sobre HTTPS:"
curl -sSk -D - -o /dev/null --max-time 10 "https://localhost/" | grep -i "strict-transport-security" | sed 's/^/     /'

echo ""
b "→ Paso 5: probar que HTTP redirige a HTTPS..."
redir=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 "http://localhost/")
loc=$(curl -sSI --max-time 10 "http://localhost/" | grep -i "^location:" | tr -d '\r' | sed 's/^/     /')
echo "   GET http://localhost/   → HTTP $redir (redirect)"
[ -n "$loc" ] && echo "$loc"

echo ""
b "→ Paso 6: el WAF sigue activo sobre HTTPS (defensa no se pierde con TLS)..."
waf_https=$(curl -sSk -o /dev/null -w "%{http_code}" --max-time 10 "https://localhost/actuator/prometheus")
echo "   GET https://localhost/actuator/prometheus → HTTP $waf_https (debe ser 403)"

echo ""
echo "==============================================================="
if [[ "$code_https" == "200" && ( "$redir" == "308" || "$redir" == "301" || "$redir" == "302" ) && "$waf_https" == "403" ]]; then
    ok " ✓ HSTS legítimo (HTTPS 200), HTTP→HTTPS ($redir), y el WAF sigue"
    ok "   bloqueando sobre TLS (403). Terminación TLS en el Ingress OK."
else
    wn " ! Revisar números (https=$code_https http=$redir waf=$waf_https)."
fi
echo "==============================================================="
