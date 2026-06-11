# Preguntas técnicas frecuentes · WAF para The Store

> Preguntas habituales sobre el diseño y la operación del WAF, con respuestas
> breves. Cada una remite a la sección del
> [documento técnico](../pre-analysis/pre-entrega/documento-final-tpe-waf.md) o al
> archivo donde está el detalle.

---

## Diseño y alternativas

### 1. ¿Por qué un WAF y no arreglar las vulnerabilidades en el código?

Las dos cosas no compiten: el WAF es **defensa en profundidad**, no un reemplazo
de código seguro (documento final §7). El argumento de diseño es que The Store es
multi-lenguaje (Java, Go, Node): arreglar el `ProxyController`, el checkout y el
Actuator exige cambios distribuidos en tres stacks distintos, mientras que el WAF
aplica **una política unificada en el único punto de entrada** sin tocar código
de negocio. En un escenario real harías ambas: el WAF te contiene *hoy*, el fix
de código llega con su ciclo de release.

### 2. ¿Por qué ModSecurity v3 sobre ingress-nginx y no otra opción?

Porque el control point ya existía: **todo el tráfico externo ya pasaba por
`ingress-nginx`**, y la imagen oficial del controller trae `libmodsecurity` y el
CRS pre-compilados — se activan por ConfigMap, sin imágenes custom ni un hop
extra de red. Alternativas consideradas: un proxy WAF separado (otro hop, más
superficie operativa), un cloud WAF (no aplica a un POC local en Kind) y
**Coraza** (sucesor de ModSec en Go, compatible con CRS), que queda como trabajo
futuro (§7).

### 3. ¿Qué es el OWASP CRS y por qué además escribieron reglas custom?

El CRS es el set de reglas genéricas de la comunidad OWASP: cubre clases enteras
de ataque (XSS `941xxx`, SQLi `942xxx`, scanners `913xxx`) sin saber nada de tu
app. La división de trabajo fue deliberada y se validó en la práctica (§8): el
**CRS resolvió las inyecciones del checkout sin una línea custom**, y las 5
reglas propias (`99001`-`99020`) cubren lo que el CRS no puede conocer: que
*esta* app expone Spring Actuator, que *esta* app tiene un `/proxy/**`
traversable, y que `/actuator/health` debe quedar whitelisted.

### 4. ¿Qué es el Paranoia Level? ¿Por qué PL1 y no PL2+?

El PL regula cuán agresivo es el CRS: a mayor nivel, más reglas activas y más
sensibilidad, pero también más **falsos positivos**. Ya en PL1 tuvimos que
whitelistear un FP (regla `920350`, Host numérico, disparaba con
`Host: 127.0.0.1` legítimo del POC — regla custom `99020`). PL2+ habría exigido
una ronda de tuning larga sobre los endpoints legítimos de la app, que excede el
scope del POC (§6.3, §7). El criterio profesional es ese: el PL se sube con
tuning iterativo midiendo FPs, no por default.

### 5. ¿Cómo decide el CRS bloquear? (anomaly scoring)

El CRS no bloquea por regla individual: cada match suma un **score parcial** y la
regla `949110` deniega cuando la suma supera el umbral. Por eso en el audit log
de un mismo request de XSS aparecen varias reglas `941xxx` y al final `949110`
(documento final §5.3). Nuestras reglas custom en cambio son `deny` directo,
porque sobre un patrón específico de la app no hay ambigüedad.

---

## Limitaciones

### 6. ¿Qué pasa con el tráfico entre pods (este-oeste)?

**El WAF no lo ve, y lo decimos explícitamente** (§3 y §7): se inserta en el
límite norte-sur (Internet → cluster); el tráfico `ui` → `catalog` va de pod a
pod sin pasar por el Ingress. Hay una demo guionada que lo prueba en vivo
([demo-north-south-vs-east-west.sh](../deploy/waf/demos/demo-north-south-vs-east-west.sh)):
el mismo request que el WAF bloquea desde afuera, hecho con `kubectl exec` desde
un pod, llega al backend. Mitigación: NetworkPolicies o un service mesh con mTLS
— trabajo futuro.

### 7. ¿Se puede bypassear el WAF? ¿Qué pasa con triple URL-encoding?

Sí — un WAF de firmas es evadible y lo declaramos (§7). La regla `99002` detecta
`..`, `%2e%2e` (encoded) y `%252e%252e` (doble encoded); un triple encode u
ofuscaciones Unicode podrían escaparse de la regla custom, aunque el CRS tiene
sus propias reglas de validación de encoding que suman score. La respuesta
en la práctica: la defensa contra evasión es **capas** (CRS + custom + fix de código +
NetworkPolicies), no una regex perfecta.

### 8. La CSP está en Report-Only — ¿eso no es "no hacer nada"?

Es **observabilidad antes que enforcement**, una decisión de diseño: una CSP estricta rompía los estilos/scripts inline de la UI (§6.6).
Report-Only reporta violaciones sin bloquear, lo que permite validar
compatibilidad antes de enforcear. El riesgo principal que cubriría (clickjacking)
queda cerrado por `X-Frame-Options: SAMEORIGIN`, que **sí** aplica. Pasar a
enforcement es cambiar el nombre del header, una vez validada la UI.

### 9. ¿El WAF protege ataques de lógica de negocio?

No (§7): abusar de un cupón N veces o un checkout con datos coherentes pero
fraudulentos pasa cualquier firma. Eso requiere reglas de negocio en la app o
bot management. El WAF cubre la capa de **patrones de ataque HTTP**, no la
semántica del negocio.

---

## Implementación y tuning (el aprendizaje real)

### 10. ¿Qué fue lo más difícil de hacer andar?

El **tuning operativo**, no las reglas (§6, §8). Los dos ejemplos para contar:
(1) `ingress-nginx` envuelve el `modsecurity-snippet` en comillas simples, así
que cualquier `'` de una regla rompía el parseo de nginx — por eso las reglas
viven en un archivo aparte montado como volumen y cargado con `Include`;
(2) un bloqueo ciego de `/actuator/*` también bloqueaba `/actuator/health`, que
Kubernetes usa para los probes — habría puesto el pod del UI en restart loop. La
regla `99001` lo excluye con un negative lookahead.

### 11. ¿Para qué sirve DetectionOnly y cómo lo muestran?

Es el modo de adopción real de un WAF: `SecRuleEngine DetectionOnly` **loguea lo
que habría bloqueado sin bloquear**, para medir falsos positivos sobre tráfico
real antes de pasar a `On`. La demo
([demo-detection-only.sh](../deploy/waf/demos/demo-detection-only.sh)) muestra el
mismo ataque devolviendo `200` con alerta en el audit log (DetectionOnly) y
`403` (On). En producción nadie prende un WAF en `On` de entrada.

### 12. ¿Por qué el rate limit devuelve 429 y no 503?

`429 Too Many Requests` es el código semánticamente correcto para throttling;
el default de nginx (`503`) significa "servicio no disponible" y confunde el
diagnóstico (¿me limitaron o se cayó el backend?). Se fuerza con
`limit-req-status-code: "429"` en el ConfigMap. Mecanismo subyacente:
`limit_req_zone` (leaky bucket, 10 rps por IP) con burst ×3.

---

## Verificación (por qué los tests demuestran lo que dicen)

### 13. ¿Cómo saben que el 403 lo puso el WAF y no otra cosa?

Tres evidencias que cierran el círculo: (1) el **experimento controlado** — los
scripts `01-pre-waf` y `02-post-waf` ejecutan el ataque idéntico y lo único que
cambia entre corridas es el WAF (`200` con ~19 KB de métricas → `403`);
(2) el **audit log** registra cada bloqueo con el ID de regla (`WAF-TS-99001`),
o sea sabemos *qué regla* disparó, no sólo el código HTTP; (3) los tests
distinguen bloqueo real de falso verde — p. ej. `curl --path-as-is`, porque sin
ese flag curl normaliza el `../` del lado cliente y el `404` resultante
*parecería* un bloqueo sin que el WAF hiciera nada (§6.5).

### 14. ¿Por qué el test de rate limit manda 100 requests concurrentes?

Porque un loop secuencial de curls nunca supera los 10 rps (cada request tarda) y
daría 100×`200` con el rate limit perfectamente activo (§6.4). Con `xargs -P 50`
el burst agota la ventana (10 rps × burst 3 = 30) y nginx throttlea el resto con
`429`. Es el ejemplo de que el test está diseñado para poder **fallar**: si no
hay concurrencia, no se está probando nada.

### 15. ¿Cómo verifican que el WAF no rompe la app?

La suite post-WAF no sólo espera bloqueos: los tests H0 y H4.b exigen que `/` y
`/actuator/health` sigan en `200` — si la whitelist de `health` fallara,
Kubernetes mataría el pod del UI por probes fallidos. Además los e2e tests de la
app corren **antes** de instalar el WAF en `create-cluster --with-waf`, a
propósito, para que el rate limit no throttlee el tráfico legítimo de la suite
(documento final §4.3).

### 16. Si algo falla al ejecutar, ¿qué revisar?

En orden: `kubectl -n ingress-nginx logs deployment/ingress-nginx-controller
--tail=50` (¿cargó la config? ¿error de parseo?), el audit log
(`kubectl exec ... tail /tmp/modsec_audit.log` — ¿disparó la regla esperada?), y
la tabla de troubleshooting del [README](../README.md#troubleshooting) (cluster
Kind corrupto, `ImagePullBackOff`, `503` transitorio post-rollout). El
`install.sh` además corre smoke-tests al final, así que un despliegue roto se ve
en el momento, no en la demo.
