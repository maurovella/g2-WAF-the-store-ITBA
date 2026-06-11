// =============================================================================
// Manifiesto de ataques de la demo · TPE Tema 9 · WAF para The Store
// =============================================================================
// Cada ataque es el MISMO que corre la suite (pre-analysis/tests/01 y 02), pero
// descrito de forma estructurada para que el front lo muestre: qué hace, por qué
// es un ataque, el comando exacto, y qué se espera antes/después del WAF.
//
// `args` se pasa a execFile('curl', args) SIN shell → no hay inyección posible.
// El marcador ___HTTP___ separa el body del status code en la salida de curl.
// =============================================================================

const HOST = process.env.DEMO_TARGET || "http://localhost";
const W = ["-w", "\\n___HTTP___%{http_code}"];
const BASE = ["-s", "-S", "--max-time", "12"];

const attacks = [
  {
    id: "h4-prometheus",
    category: "H4",
    title: "Exfiltración de /actuator/prometheus",
    why: "Spring Actuator publica ~19 KB de telemetría interna (memoria, threads, endpoints, versiones) a cualquier cliente anónimo. Information disclosure de manual (CWE-200) y base de reconocimiento para todo lo demás.",
    display: `curl -i ${HOST}/actuator/prometheus`,
    type: "http",
    args: [...BASE, ...W, `${HOST}/actuator/prometheus`],
    expectPre: 200,
    expectPost: 403,
    blocks: "regla custom 99001",
  },
  {
    id: "h4-actuator-index",
    category: "H4",
    title: "Índice /actuator (mapa HAL de endpoints)",
    why: "El índice sin sufijo lista en formato HAL TODOS los endpoints actuator disponibles — un mapa de reconocimiento que le ahorra el trabajo al atacante.",
    display: `curl -i ${HOST}/actuator`,
    type: "http",
    args: [...BASE, ...W, `${HOST}/actuator`],
    expectPre: 200,
    expectPost: 403,
    blocks: "regla custom 99001 (índice)",
  },
  {
    id: "h1-traversal",
    category: "H1",
    title: "Path traversal / SSRF vía /proxy/*",
    why: "El endpoint /proxy reenvía al backend sin validar el path. Con `..` se sale del scope del servicio y se alcanza /actuator/info interno. --path-as-is evita que curl normalice el `..` del lado cliente.",
    display: `curl --path-as-is -i ${HOST}/proxy/catalog/../../actuator/info`,
    type: "http",
    args: [...BASE, "--path-as-is", ...W, `${HOST}/proxy/catalog/../../actuator/info`],
    expectPre: 200,
    expectPost: 403,
    blocks: "regla custom 99002",
  },
  {
    id: "h1-proxy-no-session",
    category: "H1",
    title: "/proxy/carts/test sin cookie de sesión",
    why: "El proxy responde con datos del backend carts sin exigir autenticación. Un navegador legítimo siempre trae la cookie SESSIONID (emitida en la 1ra visita); un curl/scanner directo no.",
    display: `curl -i ${HOST}/proxy/carts/test`,
    type: "http",
    args: [...BASE, ...W, `${HOST}/proxy/carts/test`],
    expectPre: 200,
    expectPost: 403,
    blocks: "reglas custom 99004/99005",
  },
  {
    id: "h2-xss",
    category: "H2",
    title: "XSS reflejado en el checkout",
    why: "El formulario de checkout acepta un payload <script> sin sanitizar. Clásico vector de robo de sesión. Lo caza el CRS base (familia 941xxx, libinjection) sin regla custom.",
    display: `curl -X POST ${HOST}/checkout --data-urlencode "firstName=<script>alert(1)</script>" ...`,
    type: "http",
    args: [...BASE, ...W, "-X", "POST", `${HOST}/checkout`,
      "--data-urlencode", "firstName=<script>alert(1)</script>",
      "--data-urlencode", "lastName=Doe", "--data-urlencode", "email=a@b.com",
      "--data-urlencode", "address1=100 Main", "--data-urlencode", "city=Anytown",
      "--data-urlencode", "state=CA", "--data-urlencode", "zipCode=11111"],
    expectPre: 200,
    expectPost: 403,
    blocks: "CRS 941xxx (XSS)",
  },
  {
    id: "h2-sqli",
    category: "H2",
    title: "SQL injection en el checkout",
    why: "Payload SQLi en firstName que llega crudo al backend. Lo caza el CRS base (familia 942xxx, libinjection) sin regla custom.",
    display: `curl -X POST ${HOST}/checkout --data-urlencode "firstName=Robert'); DROP TABLE addresses;--" ...`,
    type: "http",
    args: [...BASE, ...W, "-X", "POST", `${HOST}/checkout`,
      "--data-urlencode", "firstName=Robert'); DROP TABLE addresses;--",
      "--data-urlencode", "lastName=Doe", "--data-urlencode", "email=a@b.com",
      "--data-urlencode", "address1=100 Main", "--data-urlencode", "city=A",
      "--data-urlencode", "state=CA", "--data-urlencode", "zipCode=11111"],
    expectPre: 200,
    expectPost: 403,
    blocks: "CRS 942xxx (SQLi)",
  },
  {
    id: "h6-scanner-ua",
    category: "H6",
    title: "User-Agent de scanner (sqlmap)",
    why: "Las herramientas automáticas (sqlmap, nikto, nuclei) operan con User-Agents reconocibles. Bloquearlos por reputación corta el recon automatizado de entrada.",
    display: `curl -A 'sqlmap/1.7.2#stable' -i ${HOST}/`,
    type: "http",
    args: [...BASE, ...W, "-A", "sqlmap/1.7.2#stable (https://sqlmap.org)", `${HOST}/`],
    expectPre: 200,
    expectPost: 403,
    blocks: "regla custom 99010",
  },
  {
    id: "h6-ratelimit",
    category: "H6",
    title: "Burst de 100 requests concurrentes",
    why: "Sin rate limit, un atacante enumera/scrapea sin freno. El WAF aplica 10 rps/IP (leaky bucket) + burst×3 y throttlea el resto con 429. Se necesita concurrencia real para disparar el límite.",
    display: `seq 1 100 | xargs -P 50 -I{} curl -s -o /dev/null -w "%{http_code}" ${HOST}/`,
    type: "burst",
    target: `${HOST}/`,
    count: 100,
    expectPre: "100× 200",
    expectPost: "mayoría 429",
    blocks: "nginx limit_req (10 rps + burst×3)",
  },
  {
    id: "h6-headers",
    category: "H6",
    title: "Headers de seguridad en la home",
    why: "Sin HSTS, X-Frame-Options, CSP, etc., el navegador no tiene defensas contra clickjacking, MIME-sniffing ni downgrade. El WAF los inyecta en TODAS las respuestas vía more_set_headers.",
    display: `curl -sD - -o /dev/null ${HOST}/ | grep -iE 'strict-transport|x-frame|x-content|content-security|referrer|permissions'`,
    type: "headers",
    args: [...BASE, "-D", "-", "-o", "/dev/null", `${HOST}/`],
    expectPre: "0 / 6",
    expectPost: "6 / 6",
    blocks: "annotation more_set_headers",
  },
];

module.exports = { attacks, HOST };
