# HOW-TO · Despliegue y verificación del WAF para The Store

**TPE Tema 9 · Protección de Servicios con WAF · ITBA · Redes de Información · 1C 2026 · Grupo 2**

Este documento explica, paso a paso y **reproducible desde cero**, cómo levantar
The Store sobre un cluster local de Kubernetes, instalar el WAF (ModSecurity v3 +
OWASP CRS + reglas custom) sobre el `ingress-nginx`, y verificar los cinco casos
comprometidos en la pre-entrega comparando el comportamiento **antes y después**
del WAF. Pensado para que alguien que clona el repo por primera vez pueda
reproducir toda la demo sin contexto previo.

- **Repo:** `maurovella/g2-WAF-the-store-ITBA`
- **Rama:** `feat/waf-modsecurity`
- **Tiempo estimado end-to-end:** ~15-20 min (la mayor parte es build de imágenes).

---

## 0. Resumen del flujo

```text
 git clone ──► ./local.sh create-cluster ──► ./local.sh install-waf ──► verificar
                  (Kind + ingress + app)        (ModSec + CRS + reglas)    (antes/después)
```

O todo de una sola vez:

```bash
./local.sh create-cluster --with-waf
```

---

## 1. Prerequisitos

| Herramienta | Versión testeada | Para qué | Cómo verificar |
|---|---|---|---|
| **Docker** | 24+ (Engine corriendo) | Runtime de los nodos Kind y de los builds | `docker info` |
| **Kind** | 0.20+ | Levanta el cluster Kubernetes dentro de Docker | `kind --version` |
| **kubectl** | 1.28+ | Cliente de Kubernetes | `kubectl version --client` |
| **curl** | cualquiera | Pruebas HTTP antes/después | `curl --version` |
| **bash** | 4+ | Ejecutar los scripts | `bash --version` |
| **git** | cualquiera | Clonar el repo | `git --version` |

> **Recursos:** Docker debe tener al menos ~4 GB de RAM y ~2 CPUs disponibles
> para el nodo de Kind. En Docker Desktop (macOS/Windows) se configura en
> *Settings → Resources*.

### Instalación rápida de Kind (si falta)

```bash
# Linux / macOS (amd64)
[ "$(uname -m)" = "x86_64" ] && ARCH=amd64 || ARCH=arm64
curl -Lo ./kind "https://kind.sigs.k8s.io/dl/v0.23.0/kind-$(uname | tr '[:upper:]' '[:lower:]')-${ARCH}"
chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind

# macOS con Homebrew
brew install kind kubectl

# Windows (PowerShell, con Chocolatey)
choco install kind kubernetes-cli
```

---

## 2. Clonar el repo

```bash
git clone https://github.com/maurovella/g2-WAF-the-store-ITBA.git
cd g2-WAF-the-store-ITBA
git checkout feat/waf-modsecurity
```

Estructura relevante:

```text
local.sh                       # orquestador raíz (cluster + app + WAF)
deploy/waf/
  ├── 01-controller-configmap.yaml      # ModSec + CRS + Include de reglas
  ├── 02-the-store-ingress.yaml         # rate limit + 6 headers + ModSec per-Ingress
  ├── 03-controller-deployment-patch.yaml  # monta las reglas como volumen
  ├── rules/the-store.conf              # reglas custom 99001-99020
  ├── install.sh / uninstall.sh         # instalador / revert idempotentes
  ├── demos/                            # 4 demos guionadas
  └── HOWTO.md                          # este documento
pre-analysis/
  ├── tests/01-pre-waf-attacks.sh       # suite de ataques (espera "vulnerable")
  ├── tests/02-post-waf-attacks.sh      # misma suite, espera "bloqueado" (23 checks)
  └── evidencias/                       # baseline pre-WAF + resultados post-WAF + audit log
```

---

## 3. Levantar el cluster + la app

```bash
./local.sh create-cluster --skip-tests
```

Qué hace este comando (ver `local.sh`):

1. Verifica prerequisitos (Docker corriendo, `kind`, `kubectl`).
2. Crea un cluster Kind de un nodo con los puertos **80/443 del host mapeados**
   al nodo (`extraPortMappings`) y la label `ingress-ready=true`.
3. Instala el `ingress-nginx` (manifest oficial para Kind, `controller-v1.13.1`).
4. Buildea las 5 imágenes (`catalog cart checkout orders ui`) y las carga en Kind.
5. Despliega The Store en el namespace `the-store` y espera a que todo esté `Ready`.

> Se usa `--skip-tests` para no correr la suite e2e ahora (la corremos nosotros
> en el paso de verificación). Si querés la corrida e2e completa, omití el flag.

Verificar que la app responde **sin WAF** todavía:

```bash
curl -s -o /dev/null -w "home: %{http_code}\n" http://localhost/
# Esperado: home: 200
```

---

## 4. (Opcional pero recomendado) Capturar el baseline pre-WAF

Antes de instalar el WAF, corré la suite de ataques: **deberían pasar** (es decir,
los ataques funcionan → la app es vulnerable). Esto es la foto "antes".

```bash
bash pre-analysis/tests/01-pre-waf-attacks.sh | tee /tmp/baseline-pre-waf.txt
```

Spot-checks manuales de los 5 casos **antes** del WAF:

```bash
# Caso 1 · Spring Actuator expuesto → fuga de métricas
curl -s -o /dev/null -w "actuator/prometheus: %{http_code}\n" http://localhost/actuator/prometheus
# Esperado SIN WAF: 200   (fuga de ~19 KB de métricas internas)

# Caso 2 · Path traversal / SSRF vía /proxy/*
curl -s --path-as-is -o /dev/null -w "traversal: %{http_code}\n" \
  "http://localhost/proxy/catalog/../../actuator/info"
# Esperado SIN WAF: 200

# Caso 3 · Scanner conocido (User-Agent)
curl -s -o /dev/null -w "nikto-UA: %{http_code}\n" -A 'Mozilla/5.00 (Nikto/2.5.0)' http://localhost/
# Esperado SIN WAF: 200

# Caso 4 · Sin rate limit (burst concurrente)
seq 1 100 | xargs -P 50 -I{} curl -s -o /dev/null -w "%{http_code}\n" http://localhost/ | sort | uniq -c
# Esperado SIN WAF: 100 respuestas 200 (ningún 429)

# Caso 5 · Headers de seguridad ausentes
curl -s -D - -o /dev/null http://localhost/ | grep -iE \
  '^(strict-transport-security|x-frame-options|x-content-type-options|content-security-policy|referrer-policy|permissions-policy):'
# Esperado SIN WAF: 0 líneas (ningún header de seguridad)
```

---

## 5. Instalar el WAF

```bash
./local.sh install-waf
```

(equivalente directo: `bash deploy/waf/install.sh`)

Qué hace `install.sh`, en orden:

1. **Verifica prerequisitos** (cluster accesible, namespaces `ingress-nginx` y
   `the-store`, controller existente).
2. **Crea la ConfigMap `modsec-custom-rules`** desde `rules/the-store.conf`
   (las reglas custom 99001-99020).
3. **Aplica `01-controller-configmap.yaml`** → activa `enable-modsecurity`,
   `enable-owasp-modsecurity-crs`, fuerza `429` en rate limit, `SecRuleEngine On`,
   audit log en `/tmp/modsec_audit.log`, e incluye las reglas custom.
4. **Patchea el Deployment** (`03-controller-deployment-patch.yaml`) para montar
   las reglas como volumen en `/etc/nginx/modsecurity-custom/`.
5. **Aplica `02-the-store-ingress.yaml`** → rate limit por IP (10 rps, burst×3),
   6 security headers (`more_set_headers`) y CSP en modo Report-Only.
6. **Reinicia el controller** (`rollout restart`) y espera a que vuelva a `Ready`.
7. **Smoke test** automático: home 200, `/actuator/prometheus` 403, UA sqlmap 403,
   6/6 headers presentes.

Al terminar deberías ver `✓ WAF instalado y verificado.`

---

## 6. Verificar los 5 casos DESPUÉS del WAF

Repetí exactamente los mismos comandos del paso 4. Ahora el resultado se invierte:

```bash
# Caso 1 · Actuator → BLOQUEADO por regla custom 99001
curl -s -o /dev/null -w "actuator/prometheus: %{http_code}\n" http://localhost/actuator/prometheus
# Esperado CON WAF: 403

# Caso 2 · Path traversal → BLOQUEADO por regla custom 99002
curl -s --path-as-is -o /dev/null -w "traversal: %{http_code}\n" \
  "http://localhost/proxy/catalog/../../actuator/info"
# Esperado CON WAF: 403

# Caso 3 · Scanner UA → BLOQUEADO por regla custom 99010
curl -s -o /dev/null -w "nikto-UA: %{http_code}\n" -A 'Mozilla/5.00 (Nikto/2.5.0)' http://localhost/
# Esperado CON WAF: 403

# Caso 4 · Rate limit ACTIVO (nginx limit_req 10 rps + burst×3)
seq 1 100 | xargs -P 50 -I{} curl -s -o /dev/null -w "%{http_code}\n" http://localhost/ | sort | uniq -c
# Esperado CON WAF: una parte 200 y el resto 429 (≈ 23/100 → 429)

# Caso 5 · 6 headers de seguridad PRESENTES
curl -s -D - -o /dev/null http://localhost/ | grep -iE \
  '^(strict-transport-security|x-frame-options|x-content-type-options|content-security-policy-report-only|referrer-policy|permissions-policy):'
# Esperado CON WAF: 6 líneas
```

### Y lo más importante: el tráfico legítimo sigue funcionando

```bash
curl -s -o /dev/null -w "home: %{http_code}\n"               http://localhost/
curl -s -o /dev/null -w "actuator/health: %{http_code}\n"    http://localhost/actuator/health
# Esperado: home: 200  ·  actuator/health: 200
```

`/actuator/health` se preserva a propósito (la regla 99001 lo excluye) porque
Kubernetes lo usa para los probes de readiness/liveness del pod del UI;
bloquearlo tumbaría la app.

### Verificación automatizada (la suite de 23 checks)

En lugar de los spot-checks manuales, podés correr la suite completa:

```bash
bash pre-analysis/tests/02-post-waf-attacks.sh
```

Resultado esperado:

```text
RESUMEN · TESTS POST-WAF
  Pasaron:  23 / 23
  Fallaron: 0 / 23
```

### Tabla resumen antes/después

| # | Caso | Pre-WAF | Post-WAF | Qué lo bloquea |
|---|------|---------|----------|----------------|
| 1 | `GET /actuator/prometheus` | `200` (fuga ~19 KB) | `403` | regla custom `99001` |
| 2 | Traversal `/proxy/catalog/../../actuator/info` | `200` | `403` | regla custom `99002` |
| 3 | `User-Agent: Nikto / sqlmap / nuclei` | `200` | `403` | regla custom `99010` |
| 4 | Burst de 100 requests concurrentes a `/` | 100×`200` | ≈23×`429` | nginx `limit_req` (10 rps) |
| 5 | Headers de seguridad en la home | 0/6 | 6/6 | annotation `more_set_headers` |

---

## 7. Cómo leer el audit log de ModSecurity

Cada vez que una regla bloquea, ModSecurity escribe una entrada en
`/tmp/modsec_audit.log` dentro del pod del controller. Para extraerlo:

```bash
kubectl -n ingress-nginx exec deployment/ingress-nginx-controller -- \
  tail -200 /tmp/modsec_audit.log
```

Para verlo "en vivo" mientras lanzás ataques desde otra terminal:

```bash
kubectl -n ingress-nginx exec deployment/ingress-nginx-controller -- \
  tail -f /tmp/modsec_audit.log
```

### Anatomía de una entrada

El audit log usa formato serial con las partes `ABCFHZ`:

| Parte | Contenido |
|---|---|
| **A** | Cabecera: timestamp, ID único de transacción, IP origen/destino |
| **B** | Request headers (método, URL, User-Agent, Host, ...) |
| **C** | Request body (si aplica, p. ej. el form del checkout) |
| **F** | Response headers |
| **H** | **Audit trail**: aquí está la línea `Message: ... [id "99001"] ...` que dice **qué regla disparó, con qué mensaje y qué acción** (`Access denied with code 403`) |
| **Z** | Separador de fin de transacción |

Ejemplo de la línea clave (parte H) que verás al pegarle a `/actuator/prometheus`:

```text
Message: Access denied with code 403 (phase 1). ... [id "99001"]
[msg "WAF-TS-99001 Acceso bloqueado a endpoint sensible de Spring Actuator"]
[tag "the-store/H4-actuator-exposed"] [severity "CRITICAL"]
```

Y para un ataque cubierto por el **OWASP CRS** (XSS/SQLi en el checkout) verás
IDs de la familia `941xxx`/`942xxx` y la regla de scoring `949110`
(*anomaly score exceeded*). Eso demuestra la **defensa en profundidad**: reglas
custom para la lógica propia de The Store + CRS para los ataques genéricos de
capa 7.

> Hay una copia versionada del audit log de una corrida real en
> [`pre-analysis/evidencias/post-waf/02-modsec_audit.log.txt`](../../pre-analysis/evidencias/post-waf/02-modsec_audit.log.txt),
> útil para la presentación si no querés depender de un ataque en vivo.

---

## 8. Demos guionadas (opcional, para la exposición)

En `deploy/waf/demos/` hay 4 scripts listos para correr en vivo:

```bash
bash deploy/waf/demos/demo-rate-limit-per-ip.sh        # rate limit por IP (429)
bash deploy/waf/demos/demo-detection-only.sh           # DetectionOnly vs On
bash deploy/waf/demos/demo-north-south-vs-east-west.sh # superficie norte-sur vs este-oeste
bash deploy/waf/demos/demo-tls-hsts.sh                 # headers TLS/HSTS
```

---

## 9. Revertir el WAF (volver al estado pre-WAF)

```bash
./local.sh uninstall-waf      # equivalente: bash deploy/waf/uninstall.sh
```

Restaura la ConfigMap default del controller (sin ModSec/CRS), reaplica el
Ingress original sin annotations y reinicia el controller. Útil para mostrar el
"antes" de nuevo o para iterar. Verificación:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/actuator/prometheus
# Vuelve a 200 (ya no hay WAF bloqueando)
```

---

## 10. Limpieza total

```bash
./local.sh delete-cluster
```

Borra el cluster Kind completo (con la app y el WAF). No deja nada en el host.

---

## 11. Troubleshooting

| Síntoma | Causa probable | Solución |
|---|---|---|
| `install-waf` dice "Cluster does not exist" | No corriste `create-cluster` | Levantá el cluster primero |
| La home responde `503` justo tras instalar | El controller todavía recargando | Esperá ~10 s y reintentá; `install.sh` ya hace `rollout status` |
| Los ataques NO se bloquean (siguen 200) | El controller no tomó la config | `kubectl -n ingress-nginx rollout restart deployment ingress-nginx-controller` |
| El rate-limit no dispara 429 | Requests secuenciales (lentas) | Hay que mandarlas **concurrentes** (`xargs -P 50`), si no quedan bajo 10 rps |
| El traversal da `404` en vez de `403` | `curl` normalizó el `../` del lado cliente | Usá `curl --path-as-is` para que el `..` literal llegue al WAF |
| Puerto 80 ocupado al crear el cluster | Otro servicio usa el 80 del host | Liberá el puerto 80 o cambialo en el `extraPortMappings` de `local.sh` |
| `kubectl` no conecta | Kind no terminó de levantar | `kubectl cluster-info`; reintentá tras unos segundos |

Logs útiles para depurar:

```bash
# Logs del controller (incluye errores de parseo de reglas)
kubectl -n ingress-nginx logs deployment/ingress-nginx-controller --tail=100

# Estado de pods de la app
kubectl -n the-store get pods

# Audit log de ModSecurity
kubectl -n ingress-nginx exec deployment/ingress-nginx-controller -- tail -200 /tmp/modsec_audit.log
```
