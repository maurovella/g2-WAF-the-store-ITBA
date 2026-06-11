# Demo web en vivo · WAF para The Store

Página local minimalista para **demostrar el WAF en vivo**: lanza los ataques
reales contra el cluster, muestra el código de cada uno y su output (status +
respuesta), y permite **togglear el WAF** para repetir la suite con el firewall
levantado o apagado. Es la versión interactiva de los scripts
[`pre-analysis/tests/`](../../../pre-analysis/tests/).

## Requisitos

- Cluster Kind levantado con The Store (`./local.sh create-cluster --skip-tests`).
- `node` (≥16) y `curl` en el PATH. **Sin dependencias npm** — usa sólo Node nativo.

## Levantar

```bash
cd deploy/waf/demo-web
node server.js
# ▶ http://localhost:7099
```

Abrí **http://localhost:7099** en el navegador.

Variables opcionales:

```bash
PORT=8080 node server.js               # otro puerto
DEMO_TARGET=http://localhost node server.js   # otro target (default http://localhost)
```

## Cómo se usa en la demo

1. **Estado del WAF** — el badge arriba indica si está activo (verde, bloqueando)
   o apagado (rojo, app vulnerable). Se detecta probando `/actuator/prometheus`.
2. **Con el WAF apagado** (`Desinstalar WAF`) → ejecutá los ataques: casi todos
   responden `200` → **la app es vulnerable** (rojo).
3. **Con el WAF activo** (`Instalar WAF`, ~30 s) → repetí: ahora responden
   `403`/`429` → **bloqueados** (verde). Mismo ataque, único cambio: el WAF.
4. **Correr toda la suite** lanza los 9 casos de una.

Cada card muestra el **comando `curl` exacto** (el mismo de la suite) y, al
ejecutar, el **status real + un fragmento de la respuesta** del cluster.

## Cómo funciona (arquitectura)

```
navegador ──fetch──► server.js (Node, :7099) ──execFile('curl')──► http://localhost (cluster)
```

- El navegador no puede correr todos los ataques directamente (prohíbe setear
  `User-Agent`, y CORS oculta las respuestas de otro origen). Por eso un
  **servidor local** ejecuta los `curl` reales y le devuelve el resultado al front.
- **Seguridad:** `execFile('curl', args)` se invoca **sin shell** y los `args`
  salen de un manifiesto fijo ([`attacks.js`](attacks.js)), nunca de input del
  usuario → no hay inyección de comandos. Pensado para uso **local** en la demo.

## Archivos

| Archivo | Qué es |
|---|---|
| [`server.js`](server.js) | Servidor Node nativo: sirve la página y ejecuta los ataques / toggle del WAF. |
| [`attacks.js`](attacks.js) | Manifiesto de los 9 ataques: título, por qué, comando, esperado pre/post, qué lo bloquea. |
| [`public/index.html`](public/index.html) | Frontend autocontenido (HTML + CSS + JS inline). |

## Endpoints del API (por si se quiere scriptear)

| Método | Ruta | Qué hace |
|---|---|---|
| `GET` | `/api/state` | `{wafActive, target}` — detecta si el WAF bloquea. |
| `GET` | `/api/attacks` | Manifiesto de ataques (sin los args internos). |
| `POST` | `/api/attack` | `{id}` → ejecuta un ataque, devuelve `{status, blocked, bodySnippet}`. |
| `POST` | `/api/suite` | Corre los 9 ataques y devuelve el array de resultados. |
| `POST` | `/api/waf` | `{action: "install"\|"uninstall"}` → corre `local.sh` (lento, ~30 s). |
