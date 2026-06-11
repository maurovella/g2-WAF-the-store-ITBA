// =============================================================================
// Servidor de la demo en vivo · WAF para The Store
// =============================================================================
// Node nativo (http + child_process), SIN dependencias externas. Sirve la página
// y ejecuta los curl reales contra el cluster (mismos comandos que la suite), así
// no hay límites de CORS ni del navegador (que prohíbe setear User-Agent).
//
// Seguridad: execFile('curl', argsArray) NO usa shell → no hay inyección. Los
// args salen del manifiesto fijo (attacks.js), nunca de input del usuario.
//
//   node server.js            # escucha en http://localhost:7099
//   PORT=8080 node server.js
// =============================================================================

const http = require("http");
const fs = require("fs");
const path = require("path");
const { execFile } = require("child_process");
const { attacks, HOST } = require("./attacks");

const PORT = process.env.PORT || 7099;
const REPO_ROOT = path.resolve(__dirname, "../../..");
const MARK = "___HTTP___";

// ---- helpers ---------------------------------------------------------------
function runCurl(args, timeout = 15000) {
  return new Promise((resolve) => {
    execFile("curl", args, { timeout, maxBuffer: 1024 * 1024 }, (err, stdout) => {
      resolve(stdout || "");
    });
  });
}

function splitStatus(out) {
  const i = out.lastIndexOf(MARK);
  if (i === -1) return { body: out, status: 0 };
  return { body: out.slice(0, i), status: parseInt(out.slice(i + MARK.length).trim(), 10) || 0 };
}

const isBlocked = (s) => s === 403 || s === 406 || s === 429 || s === 451;

async function runHttp(a) {
  const { body, status } = splitStatus(await runCurl(a.args));
  const snippet = body.replace(/\s+$/, "").slice(0, 600);
  return { status, blocked: isBlocked(status), bodySnippet: snippet };
}

async function runHeaders(a) {
  const out = await runCurl(a.args);
  const wanted = [
    "strict-transport-security", "x-frame-options", "x-content-type-options",
    "content-security-policy-report-only", "referrer-policy", "permissions-policy",
  ];
  const present = wanted.filter((h) => new RegExp("^" + h + ":", "im").test(out));
  return {
    status: present.length === 6 ? 200 : 0,
    blocked: present.length === 6, // "bloqueado" = mitigado: los 6 headers presentes
    bodySnippet: out.split("\n").filter((l) => /^(strict-transport|x-frame|x-content|content-security|referrer|permissions)/i.test(l)).join("\n") || "(ningún header de seguridad presente)",
    headersPresent: present.length,
  };
}

async function runBurst(a) {
  const N = a.count || 100, CONC = 50;
  let i = 0, ok = 0, throttled = 0;
  async function worker() {
    while (i < N) {
      i++;
      const { status } = splitStatus(await runCurl(["-s", "-o", "/dev/null", "-w", MARK + "%{http_code}", "--max-time", "12", a.target], 13000));
      if (status === 200) ok++; else if (status === 429 || status === 503) throttled++;
    }
  }
  await Promise.all(Array.from({ length: CONC }, worker));
  return {
    status: throttled >= 10 ? 429 : 200,
    blocked: throttled >= 10,
    bodySnippet: `${ok}/${N} → 200 OK · ${throttled}/${N} throttleados (429/503)`,
  };
}

async function runAttack(a) {
  if (a.type === "headers") return runHeaders(a);
  if (a.type === "burst") return runBurst(a);
  return runHttp(a);
}

function wafState() {
  // El WAF está activo si /actuator/prometheus responde 403.
  return runCurl(["-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "8", `${HOST}/actuator/prometheus`])
    .then((s) => ({ wafActive: parseInt(s.trim(), 10) === 403, target: HOST }));
}

function runLocalSh(action) {
  return new Promise((resolve) => {
    const cmd = action === "install" ? "install-waf" : "uninstall-waf";
    execFile("bash", [path.join(REPO_ROOT, "local.sh"), cmd], { cwd: REPO_ROOT, timeout: 240000, maxBuffer: 4 * 1024 * 1024 },
      (err, stdout, stderr) => resolve({ ok: !err, log: (stdout || "") + (stderr || "") }));
  });
}

// ---- http server -----------------------------------------------------------
function send(res, code, body, type = "application/json") {
  res.writeHead(code, { "Content-Type": type });
  res.end(typeof body === "string" ? body : JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve) => {
    let d = ""; req.on("data", (c) => (d += c)); req.on("end", () => { try { resolve(JSON.parse(d || "{}")); } catch { resolve({}); } });
  });
}

// manifiesto público (sin los args internos de curl)
const publicAttacks = attacks.map(({ args, ...rest }) => rest);

const server = http.createServer(async (req, res) => {
  const url = req.url.split("?")[0];
  try {
    if (req.method === "GET" && (url === "/" || url === "/index.html")) {
      return send(res, 200, fs.readFileSync(path.join(__dirname, "public/index.html"), "utf8"), "text/html; charset=utf-8");
    }
    if (req.method === "GET" && url === "/api/attacks") return send(res, 200, { attacks: publicAttacks, target: HOST });
    if (req.method === "GET" && url === "/api/state") return send(res, 200, await wafState());
    if (req.method === "POST" && url === "/api/attack") {
      const { id } = await readBody(req);
      const a = attacks.find((x) => x.id === id);
      if (!a) return send(res, 404, { error: "ataque no encontrado" });
      return send(res, 200, { id, ...(await runAttack(a)) });
    }
    if (req.method === "POST" && url === "/api/suite") {
      const results = [];
      for (const a of attacks) results.push({ id: a.id, ...(await runAttack(a)) });
      return send(res, 200, { results });
    }
    if (req.method === "POST" && url === "/api/waf") {
      const { action } = await readBody(req);
      if (action !== "install" && action !== "uninstall") return send(res, 400, { error: "action inválida" });
      return send(res, 200, await runLocalSh(action));
    }
    send(res, 404, { error: "not found" });
  } catch (e) {
    send(res, 500, { error: String(e && e.message || e) });
  }
});

server.listen(PORT, () => {
  console.log(`\n  Demo WAF · The Store`);
  console.log(`  ▶ http://localhost:${PORT}`);
  console.log(`  target: ${HOST}  ·  repo: ${REPO_ROOT}\n`);
});
