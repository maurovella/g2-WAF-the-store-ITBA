# `deploy/waf/` · WAF stack para The Store

ModSecurity v3 + OWASP CRS + reglas custom, deployado sobre el `ingress-nginx` que `./local.sh` ya levanta.

## Archivos

| Archivo | Qué hace |
|---|---|
| `01-controller-configmap.yaml` | ConfigMap del `ingress-nginx-controller` con ModSec + CRS + reglas globales 99001-99020 |
| `02-the-store-ingress.yaml` | Reemplaza el Ingress de The Store con anotaciones de rate limit, 6 security headers y ModSec per-Ingress |
| `install.sh` | Instalador idempotente · aplica, reinicia el controller, smoke-test |
| `uninstall.sh` | Vuelve al estado pre-WAF |
| `rules/` | Reservado para reglas adicionales si surgen falsos positivos |

## Cómo correrlo

```bash
# Opción A · todo de una: levantar el cluster con el WAF ya instalado
./local.sh create-cluster --with-waf

# Opción B · paso a paso
# 1. Levantar el cluster (si no está)
./local.sh create-cluster --skip-tests

# 2. (Opcional) Baseline pre-WAF
bash pre-analysis/tests/01-pre-waf-attacks.sh | tee pre-analysis/evidencias/resultados-pre-waf.txt

# 3. Instalar el WAF (vía local.sh, o directo con bash deploy/waf/install.sh)
./local.sh install-waf

# 4. Tests post-WAF + captura de evidencia
bash pre-analysis/tests/collect-evidence.sh

# 5. (Opcional) Revertir
./local.sh uninstall-waf
```

> `./local.sh install-waf` y `uninstall-waf` son wrappers del controlador raíz
> sobre `deploy/waf/install.sh` / `uninstall.sh`; verifican que el cluster y el
> namespace existan antes de tocar nada. Seguís pudiendo invocar los scripts
> directamente si preferís.

## Reglas custom · cheat-sheet

| ID | Hallazgo cubierto | Qué bloquea |
|---|---|---|
| **99001** | H4 · Spring Actuator expuesto | `/actuator/{info,metrics,prometheus,env,beans,...}` · permite `/actuator/health` |
| **99002** | H1 · Path traversal vía `/proxy/*` | `/proxy/*` que contiene `..`, `%2e%2e`, `%252e%252e` |
| **99003** | H1 · refuerzo SSRF | `/proxy/<svc>/(actuator|debug|admin|management)` |
| **99010** | H6 · scanner detection | UAs `sqlmap`, `nikto`, `nuclei`, + extras |
| **99020** | Whitelist quirúrgica | Desactiva CRS-920350 solo para `Host: localhost` |

Las reglas 9xxxx son el rango reservado por OWASP CRS para reglas del usuario (no chocan con las del CRS oficial).

## Cómo extraer el audit log para la demo

```bash
kubectl -n ingress-nginx exec deployment/ingress-nginx-controller -- \
  tail -500 /tmp/modsec_audit.log
```

Cada entrada del audit log incluye:
- Timestamp del request
- Request original (método, URL, headers, body si aplica)
- ID de la regla que disparó (`id "99001"` o CRS `id "942100"` etc.)
- Acción tomada (`Access denied with code 403`)
- Match data (qué exactamente disparó la regla)

Esa info es lo que mostramos en el slide "antes/después" de la presentación oral.
