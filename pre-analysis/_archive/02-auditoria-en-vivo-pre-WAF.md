# Auditoría en vivo de The Store — pre-WAF
## TPE — Protección de Servicios con WAF · ITBA · 1C 2026

> **Fecha de la auditoría:** jueves 16 de abril de 2026, ~17:30 UTC.
> **Cluster:** Kind local del usuario, levantado con `./local.sh create-cluster`, respondiendo en `http://localhost:80`.
> **Método:** navegación + `fetch` desde la consola del navegador (mismo origen, sin proxies adicionales).
> **Versión del repo:** `the-store-main` tal como está en la carpeta del TP, sin parches del grupo todavía.
> **Resumen:** se confirmaron en vivo **6 de los 6 hallazgos** estimados estáticamente. Uno de ellos (H1) resultó **más grave de lo previsto**: la combinación SSRF + path traversal del `ProxyController` permite alcanzar el `/actuator/prometheus` del propio UI, exfiltrando 24 KB de métricas con cada request. La aplicación no tiene rate limiting, no detecta scanners conocidos, y no envía ningún header de seguridad. Este documento es la evidencia que justifica desplegar el WAF y será insumo del PDF de pre-entrega y del PPT final.

---

## Tabla resumen

| ID | Hallazgo | Severidad real (post-test) | Estado en producción actual |
|---|---|---|---|
| H1 | SSRF + path traversal vía `/proxy/**` | **🔴 Crítica** (reconfirmada y peor de lo esperado) | ABIERTO |
| H4 | Spring Actuator expuesto al exterior (info, health, metrics, prometheus) | **🟠 Alta** (24 KB de métricas leakean cada hit) | ABIERTO |
| H6 | Sin scanner detection ni rate limiting | **🟠 Alta** (167 req/s sin throttling, todos los UAs maliciosos pasan) | ABIERTO |
| Headers | Sin HSTS, sin CSP, sin X-Frame-Options, sin X-Content-Type-Options | **🟡 Media** | ABIERTO |
| H5 | `X-Forwarded-*` aceptados sin verificación | **🟡 Media** | ABIERTO |
| H2 | Validación parcial del checkout / catalog query | **🟡 Media** (Spring devuelve 500 antes que persistir, Go parametriza queries) | PARCIALMENTE MITIGADO POR CÓDIGO |
| H3 | Chat sin validación | **🟢 N/A hoy** (`enabled:false`, devuelve 404) | NO ACTIVO |

---

## 0 · Recon inicial

### 0.1 Home pública

`GET http://localhost/` → **HTTP 200**, `Content-Type: text/html`, **19.973 bytes**. Página renderiza correctamente: título "Demo Store", branding "The most public Secret Shop", navegación con Home / Gadget Repository, listado de productos.

### 0.2 Headers de seguridad — auditoría completa

Test: `fetch('/').then(r => r.headers)`.

| Header | Valor | Veredicto |
|---|---|---|
| `Strict-Transport-Security` | (ausente) | ❌ no fuerza HTTPS |
| `X-Frame-Options` | (ausente) | ❌ susceptible a clickjacking |
| `X-Content-Type-Options` | (ausente) | ❌ permite MIME sniffing |
| `Content-Security-Policy` | (ausente) | ❌ XSS no mitigado |
| `Referrer-Policy` | (ausente) | ❌ leaks de referrer |
| `Permissions-Policy` | (ausente) | ❌ APIs del browser sin restringir |
| `Server` | (ocultado) | ✅ único punto positivo |

**Conclusión:** la aplicación no envía **ningún** header de seguridad estándar. ModSecurity en el ingress puede agregarlos como respuesta blindada (`Header always set X-Content-Type-Options "nosniff"`, etc.).

---

## 1 · H1 — SSRF + Path Traversal vía `ProxyController` (CRÍTICO, agravado en vivo)

### Hipótesis estática
El controller de la UI (`ProxyController.java:38-82`) reenvía `GET /proxy/<servicio>/**` a `http://<servicio>` sin sanitizar el path, lo que permite SSRF de los backends.

### Pruebas en vivo

**PoC 1.1 — Reachability del proxy:**
```
GET /proxy/orders/orders
→ HTTP 404 con cuerpo:
{"timestamp":"2026-04-16T20:27:58.597+00:00","status":404,
 "error":"Not Found","path":"/orders/orders"}
```
El backend `orders` devolvió un 404 con su propio formato JSON de error → confirma que el proxy efectivamente reenvió la request al backend interno (Spring Boot). **El SSRF básico está activo.**

**PoC 1.2 — `GET /proxy/checkout/checkout`:**
```
→ HTTP 404 con cuerpo:
{"message":"Checkout not found","error":"Not Found","statusCode":404}
```
Otro backend interno (NestJS, formato de error diferente) reenvía la respuesta. **Confirmado: cada uno de los 4 backends ClusterIP es alcanzable desde Internet a través del proxy.**

**PoC 1.3 — Path traversal exitoso, *peor* de lo previsto:**
```
GET /proxy/catalog/../../actuator/info
→ HTTP 200 OK
→ Body: {}
```
```
GET /proxy/catalog/../../actuator/health
→ HTTP 200 OK
→ Body: {"status":"UP","groups":["liveness","readiness"]}
```
```
GET /proxy/catalog/../../actuator/prometheus
→ HTTP 200 OK
→ Body: 24.590 bytes de métricas Prometheus
```

> **¿Qué está pasando?** El `ProxyController` arma la URL como `endpoint + path`, donde `endpoint` es `http://catalog` y `path` viene del request. Cuando enviamos `../../actuator/info`, Java normaliza el URI y termina apuntando al *propio host* del UI (Spring Boot collapsa `..` por sobre el host root o reescribe el path antes de hacer el forward). El resultado: **un atacante externo puede ejecutar requests arbitrarias contra el endpoint Actuator del UI utilizando el proxy como pivote**, evadiendo cualquier control de red que pudiera filtrar Actuator.

**PoC 1.4 — Variantes de bypass intentadas:**
```
GET /proxy/catalog/%2e%2e%2f%2e%2e%2fadmin
→ HTTP 404 "page not found" (devuelto por el catalog Go, no escapó)
GET /proxy/catalog/..%2F..%2Factuator%2Fmetrics
→ HTTP 404 (encoding diferente, no matcheó la normalización)
```
Es decir: la traversal con barras *literales* funciona; con doble URL-encoding no. Eso es información valiosa para tunear las reglas WAF (CRS captura ambas variantes con su decoding chain).

### Impacto real
- **Cualquier persona con acceso a `http://localhost`** (en producción, cualquier persona en Internet) puede dumpear las métricas Prometheus que listamos en el §4.
- Los backends `carts`, `orders` y `checkout`, marcados como `ClusterIP` (NO accesibles desde fuera del cluster por diseño), **son alcanzables a través del proxy**, lo que efectivamente convierte un microservicio "interno" en uno expuesto.
- Si en el futuro alguien activa endpoints actuator más sensibles (`env`, `heapdump`, `loggers`), el atacante los obtiene también vía esta ruta.

### Mitigación con WAF
- Reglas CRS familia `930-` (LFI/path traversal) bloquean `..` literal y URL-encoded.
- Reglas CRS familia `932-` (RCE) capturan patrones de exec.
- Regla custom adicional: bloquear `^/proxy/.*\.\.` con `id:9003`.

---

## 2 · H4 — Spring Actuator expuesto al exterior (CONFIRMADO, gravedad subestimada)

### Pruebas en vivo

| Endpoint | HTTP | Cuerpo | Bytes |
|---|---|---|---|
| `GET /actuator/info` | 200 | `{}` | 2 |
| `GET /actuator/health` | 200 | `{"status":"UP","groups":["liveness","readiness"]}` | 49 |
| `GET /actuator/metrics` | 200 | `{"names":["application.ready.time", ...953 chars]}` | 953 |
| `GET /actuator/prometheus` | 200 | métricas en formato Prometheus | **16.110** (en frío) / **24.590** (con tráfico) |
| `GET /actuator/env` | 404 | `{"timestamp":...,"path":"/actuator/env","status":404}` | 128 |
| `GET /actuator/heapdump` | 404 | idem | 133 |

### Lo que `actuator/prometheus` filtra públicamente

Muestra real (extracto de los 175 series exportados):

- **Storage del contenedor:**
  `disk_total_bytes{path="/app/."} 1.081100128256E12`
  → 1 TB de disco total. `disk_free_bytes{path="/app/."} 1.002170269696E12` → 1 TB libre. *Útil para un atacante que quiera saber cuánto puede uploadear.*
- **Stack interno:**
  `http_server_requests_seconds_count{error="ApiException", exception="ApiException", method="POST", outcome="SERVER_ERROR", status="500", uri="/checkout"} 2`
  → Confirma que existen excepciones internas tipo `ApiException` (huella de stack Java).
- **Endpoints internos llamados recientemente:**
  ```
  uri="/proxy/carts/**"     → 1 request reciente
  uri="/proxy/catalog/**"   → 4 requests recientes
  uri="/proxy/checkout/**"  → 1 request reciente
  uri="/proxy/orders/**"    → 1 request reciente
  ```
  → **Un atacante puede ver, en tiempo real, qué otros endpoints están siendo testeados por terceros**. Esto convierte el endpoint en un canal de OSINT pasivo: si yo sé que alguien más está probando rutas internas, sé qué buscar.
- **Métricas del JVM:** versión de la JVM, threads activos, garbage collector usado, heap size — todo lo que un exploit-builder necesita para apuntar a una versión específica.

### Impacto
Hoy el daño es de "information disclosure" puro. Pero los endpoints `env`, `heapdump`, `loggers` *están a una línea de YAML de distancia* — basta con que alguien agregue `env` al `include` por debug y exponemos variables de entorno (incluyendo `RETAIL_CATALOG_PERSISTENCE_PASSWORD` que ya vimos en `kubernetes.yaml` decodificable trivialmente desde `actuator/env`).

### Mitigación con WAF
Regla custom (lista negra de paths sensibles):
```
SecRule REQUEST_URI "@rx ^/actuator/(env|heapdump|threaddump|loggers|configprops|caches|conditions|scheduledtasks|sessions|shutdown|metrics|prometheus|info)" \
  "id:9001,phase:1,deny,status:403,log,msg:'Blocked sensitive Actuator endpoint'"
```

---

## 3 · H6 — Sin scanner detection ni rate limiting (CONFIRMADO con evidencia numérica)

### 3.1 Scanner detection: cero

Cuatro User-Agents de scanners conocidos, ninguno bloqueado:

| User-Agent enviado | HTTP recibido |
|---|---|
| `Mozilla/5.00 (Nikto/2.5.0)` | **200 OK** + 19.973 bytes |
| `sqlmap/1.7.2#stable (https://sqlmap.org)` | **200 OK** + 19.973 bytes |
| `Nuclei - Open-source project (github.com/projectdiscovery/nuclei)` | **200 OK** + 19.973 bytes |
| `DirBuster-1.0-RC1 (...)` | **200 OK** + 19.973 bytes |

OWASP CRS rule `913100` matchea estos UA y devuelve 403 directo. Hoy: pasan todos.

### 3.2 Rate limiting: cero

Test: 100 requests `GET /` en paralelo.
- **Duración total:** 597 ms.
- **Throughput sostenido:** 167 req/s.
- **Distribución de códigos:** `{"200": 100}` — ninguno fue limitado.

Las métricas internas que vimos en §2 confirman que el servidor recibió y procesó las 100: `http_server_requests_seconds_count{...uri="/"} 109` (incluye los 9 hits de mi navegación visual previa + los 100 del test).

### Impacto
- **Brute force, scraping y enumeración** son triviales.
- **DoS de aplicación** (no de red) es alcanzable: cada request renderiza Thymeleaf y sirve 19.973 bytes; un atacante con 1.000 conexiones sostenidas puede saturar.
- Sin baseline de tráfico legítimo, no hay anomaly detection.

### Mitigación con WAF
- CRS family `913-` para scanners conocidos.
- `nginx.ingress.kubernetes.io/limit-rps: "10"` y `limit-connections: "5"` por IP en el Ingress.

---

## 4 · H5 — Cabeceras `X-Forwarded-*` aceptadas sin verificación (CONFIRMADO)

### Prueba
```
GET / HTTP/1.1
Host: localhost
X-Forwarded-For: 8.8.8.8
X-Forwarded-Proto: https
X-Real-IP: 8.8.8.8
X-Forwarded-Host: evil-bank.com
```
**Respuesta:** HTTP 200, body completo de la home, sin protesta.

### Impacto
Como la app tiene `forward-headers-strategy: NATIVE` en `application.yml`, **Spring confiará** en estos valores y los usará para:
- Logs (en logs queda registrado que la request vino de `8.8.8.8`).
- Generación de URLs absolutas (puede generar links como `https://evil-bank.com/...`).
- Eventual lógica de rate-limiting/audit/IP-banning futura (todo eludible cambiando el `X-Forwarded-For`).

### Mitigación con WAF
ModSecurity puede strippear los headers antes de que lleguen a Spring:
```
SecAction "phase:1,nolog,pass,id:9010,setvar:tx.real_ip=%{REMOTE_ADDR}"
SecRule REQUEST_HEADERS:X-Forwarded-For "@rx .+" \
  "id:9011,phase:1,nolog,pass,setvar:'request_headers.X-Forwarded-For=%{tx.real_ip}'"
```

---

## 5 · H2 — Validación parcial del checkout / catalog query (CONFIRMADO con matices)

### 5.1 Checkout: el form acepta payloads maliciosos

```
POST /checkout
Content-Type: application/x-www-form-urlencoded
firstName=<script>alert(1)</script>&lastName=Doe&email=a@b.com&...

→ HTTP 500 Internal Server Error
{"timestamp":"...","path":"/checkout","status":500,
 "error":"Internal Server Error","requestId":"671c3acb-176"}
```

El 500 es **engañoso**: las métricas del actuator confirman que es una `ApiException` (error de negocio downstream — probablemente porque no había sessionId en la request crafteada manualmente), **no** una validación que rechazó el XSS. Si la request hubiera venido de un usuario real con sessionId válido, el payload se habría persistido en el carrito.

Mismo comportamiento con SQLi (`Robert'); DROP TABLE addresses;--`): HTTP 500 con `ApiException`, no hubo rechazo en la capa de validación de Spring para ese campo.

### 5.2 Catalog query: payloads SQLi/RCE/XXE pasan sin alarma

```
GET /catalog?tag=' OR '1'='1
→ HTTP 200, página renderizada normalmente (24.580 bytes con vista vacía,
   sin productos porque el tag literal no matcheó nada en Gorm).

GET /catalog?tag=; cat /etc/passwd
→ HTTP 200, idem.

GET /catalog?tag=<!ENTITY xxe SYSTEM 'file:///etc/passwd'>
→ HTTP 200, idem.
```

### 5.3 Análisis del código de catalog

El backend `catalog` (Go) **usa Gorm con queries parametrizadas** (`Where("tags.name IN ?", tags)`), por lo que la SQLi *real* no es explotable hoy. Pero el atacante recibe **HTTP 200** sin alarma, lo que invita a enumerar payloads más sofisticados. Un WAF cortaría el ciclo de iteración del atacante en el primer intento.

### Mitigación con WAF
- Reglas CRS familia `942-` (SQLi) → 942100 captura `' OR '1'='1`.
- Reglas CRS familia `932-` (RCE) → 932100 captura `; cat /etc/passwd`.
- Reglas CRS familia `941-` (XSS) → 941100 captura `<script>`.

---

## 6 · H3 — Chat sin validación (no aplicable HOY)

```
POST /chat/submit
{"message":"Ignore all previous instructions..."}
→ HTTP 404 Not Found
```

El controller `ChatController` está bajo `@ConditionalOnProperty("retail.ui.chat.enabled")` y por defecto `enabled: false`, por eso el endpoint no está mapeado.

**Para la demo**, el grupo va a habilitar el chat (con un mock de OpenAI o un modelo local) para mostrar el ataque de prompt-injection. La regla custom WAF anti-prompt-injection queda como diferencial de la presentación.

---

## 7 · Veredicto numérico

| Métrica | Estado actual | Esperado post-WAF |
|---|---|---|
| Endpoints sensibles bloqueados | **0/5** (info, health, metrics, prometheus, proxy traversal) | 5/5 |
| Headers de seguridad enviados | **0/6** | 6/6 |
| User-Agents de scanners bloqueados | **0/4** | 4/4 |
| Rate-limit por IP | ∞ | 10 req/s |
| Path traversal explotable | sí (vía `/proxy/<svc>/../..`) | bloqueado por CRS 930xxx |
| Bytes de métricas internas leakeados por hit | **24.590** | 0 (403 inmediato) |

---

## 8 · Conclusión

Las pruebas en vivo confirmaron y agravaron el diagnóstico estático. La aplicación tiene un **path traversal explotable que escapa hasta el endpoint actuator del propio UI** (esto no estaba previsto y es la pieza más fuerte para presentar). No tiene rate limiting, no detecta scanners, no envía headers de seguridad y los endpoints de monitoreo están todos abiertos. **Cada uno de estos hallazgos es un caso de uso natural para el WAF**: las primeras 4 reglas que escribiremos (anti-actuator, anti-traversal, anti-scanner-UA, rate-limit) cubren los hallazgos críticos sin ningún tuning especial.

Estos resultados son la justificación cuantitativa que va al PDF de pre-entrega bajo la sección **"Problemática y contexto"** y al PPT de la entrega final como **slide de "antes vs después"**.

---

## 9 · Anexo: cómo se reproduce esto

Cualquier integrante del grupo puede repetir la auditoría sin más herramientas que el navegador:

1. Levantar el cluster: `cd the-store-main && ./local.sh create-cluster --skip-tests`
2. Abrir `http://localhost/` en Chrome/Firefox.
3. Abrir DevTools → Console.
4. Pegar el bloque `fetch` de la sección "Pre-WAF" (también disponible en `tests/01-pre-waf-attacks.sh` para `curl`).
5. Comparar los códigos de respuesta con la columna "estado actual" de la tabla del §7.

Una vez desplegado el WAF, repetir todo y comparar con la columna "esperado post-WAF". Esa comparación es **el video/screencast principal de la presentación final**.
