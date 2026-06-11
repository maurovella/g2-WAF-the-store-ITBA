# The Store

[![Build](https://github.com/jupmoreno/the-store/actions/workflows/main.yml/badge.svg)](https://github.com/jupmoreno/the-store/actions/workflows/main.yml)

**The Store** is a modern e-commerce platform built with microservices architecture.

Our platform provides a complete shopping experience with:
- **Beautiful storefront** with customizable themes and responsive design
- **Scalable microservices** built with multiple languages and frameworks
- **Real-time inventory management** and order processing

---

## 🛡️ TPE · Protección de Servicios con WAF (ITBA · Redes · 1C 2026 · Grupo 2)

Este repositorio extiende **The Store** con un **WAF (ModSecurity v3 + OWASP CRS +
reglas custom)** sobre `ingress-nginx`, como Trabajo Práctico Especial del Tema 9.

**Integrantes:** Mauro Vella · Enrique Castillo (68321) · Federico Inti García Lauberer (61374)
· **Rama:** `feat/waf-modsecurity`

**Prerequisitos:** Docker (Engine corriendo), Kind (≥0.20), kubectl (≥1.28), `curl` y `bash`.
Docker con ~4 GB RAM / 2 CPUs para el nodo de Kind.

### Replicación paso a paso

```bash
# 1. Cluster Kind + ingress-nginx + app (queda respondiendo en http://localhost)
./local.sh create-cluster --skip-tests
curl -s -o /dev/null -w "home: %{http_code}\n" http://localhost/   # esperado: 200

# 2. Baseline ANTES del WAF: los ataques deben FUNCIONAR (app vulnerable)
bash pre-analysis/tests/01-pre-waf-attacks.sh | tee /tmp/baseline-pre-waf.txt

# 3. Instalar el WAF (ModSecurity v3 + OWASP CRS + reglas custom 99001-99020)
./local.sh install-waf

# 4. Ataques DESPUÉS del WAF: deben quedar BLOQUEADOS (esperado: 23/23)
bash pre-analysis/tests/02-post-waf-attacks.sh

# 5. Revertir / limpiar
./local.sh uninstall-waf      # volver al estado pre-WAF
./local.sh delete-cluster     # borrar el cluster completo
```

Verificación de los 5 casos comprometidos (antes → después del WAF):

| # | Caso | Pre-WAF | Post-WAF | Qué lo bloquea |
|---|------|---------|----------|----------------|
| 1 | `GET /actuator/prometheus` | `200` (fuga ~19 KB) | `403` | regla custom `99001` |
| 2 | Traversal `/proxy/catalog/../../actuator/info` | `200` | `403` | regla custom `99002` |
| 3 | `User-Agent: Nikto / sqlmap / nuclei` | `200` | `403` | regla custom `99010` |
| 4 | Burst de 100 requests concurrentes a `/` | 100×`200` | ≈23×`429` | nginx `limit_req` (10 rps) |
| 5 | Headers de seguridad en la home | 0/6 | 6/6 | annotation `more_set_headers` |

El tráfico legítimo sigue funcionando: `http://localhost/` → `200` y `/actuator/health` → `200`
(la regla 99001 lo excluye porque Kubernetes lo usa para los probes del pod del UI).

### Troubleshooting

> ⚠️ **Antes de replicar:** usá una conexión estable y **no cambies de red ni reinicies
> Docker Desktop con el cluster levantado** — eso corrompe el nodo de Kind.

| Síntoma | Causa | Solución |
|---|---|---|
| `timed out waiting for ... ingress-nginx-controller` | El `wait` venció mientras bajaba la imagen del controller (red lenta). No está roto. | Esperar y re-correr `./local.sh create-cluster --skip-tests` (es idempotente). |
| El build se cuelga descargando (`amazonlinux:2023`, paquetes `dnf`) | Red lenta/intermitente a `public.ecr.aws` o mirrors de Amazon Linux. | Reintentar con red estable; opcional pre-bajar: `docker pull public.ecr.aws/amazonlinux/amazonlinux:2023`. |
| `The connection to the server localhost:8080 was refused` | El kubeconfig perdió el contexto del cluster. | `kind export kubeconfig --name the-store`. |
| Nodo en estado `Created`, falta `/etc/kubernetes/admin.conf` | **Docker Desktop se reinició con el cluster levantado** → nodo de Kind corrupto. | Recrear: `kind delete cluster --name the-store && ./local.sh create-cluster --skip-tests`. |
| Pods en `ImagePullBackOff` | Las imágenes no quedaron en el nodo de Kind. | Cargarlas (`for s in catalog cart checkout orders ui; do kind load docker-image "the-store-${s}:latest" --name the-store; done`) y `kubectl -n the-store delete pods --all`. |
| La home da `503` recién desplegada o tras instalar el WAF | El ingress aún no registró el endpoint / controller recargando. | Esperar ~10-30s y reintentar el `curl`. |
| El traversal da `404` en vez de `403`/`200` | `curl` normalizó el `../` del lado cliente. | Usar `curl --path-as-is`. |
| El rate-limit no dispara `429` | Requests secuenciales quedan bajo 10 rps. | Mandarlas concurrentes: `seq 1 100 \| xargs -P 50 ...`. |

### Material complementario

- [deploy/waf/HOWTO.md](deploy/waf/HOWTO.md) — detalle del WAF: reglas custom, anatomía del audit log, demos guionadas.
- [deploy/waf/demos/](deploy/waf/demos/) — 4 scripts para correr en vivo (rate limit, DetectionOnly vs On, norte-sur vs este-oeste, TLS/HSTS).
- [pre-analysis/pre-entrega/](pre-analysis/pre-entrega/) — documento final de pre-entrega y evidencias.

---

## 🏗️ Architecture

The Store is built with a microservices architecture that uses different technologies:

![Architecture](/docs/images/architecture.png)

| Service | Language | Description |
|---------|----------|-------------|
| [UI](./src/ui/) | Java (Spring Boot) | Modern web interface with themes and chat bot |
| [Catalog](./src/catalog/) | Go | Product catalog API with search and filtering |
| [Cart](./src/cart/) | Java (Spring Boot) | Shopping cart management with Redis/DynamoDB |
| [Orders](./src/orders/) | Java (Spring Boot) | Order processing and management |
| [Checkout](./src/checkout/) | Node.js (NestJS) | Checkout orchestration and payment processing |


## 🛠️ Development

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) running
- [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation) installed
- [Kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) installed

### Cluster Management

Use the `local.sh` script to manage your local Kubernetes cluster:

```bash
# Create a new cluster and deploy all services
./local.sh create-cluster

# Rebuild the entire cluster (delete and recreate)
./local.sh rebuild-cluster

# Delete the cluster
./local.sh delete-cluster

# Check cluster status
./local.sh status

# Build and load Docker images only
./local.sh reload-images
```

After running `./local.sh create-cluster`, access The Store at: **http://localhost**.

### Testing

#### E2E Testing

Run end-to-end tests to validate the complete system:

```bash
# Run e2e tests on existing cluster
./local.sh e2e-test
```

**Note**: These tests are run automatically when creating or rebuilding the cluster. You can skip them using the `--skip-tests` parameter for faster setup:

```bash
# Create cluster without running tests (faster setup)
./local.sh create-cluster --skip-tests

# Rebuild cluster without running tests
./local.sh rebuild-cluster --skip-tests
```

#### Load Testing
Run load generator tests to validate system performance:

```bash
# Run load generator tests
./local.sh load-test
```

The load generator will run performance tests against your local cluster for 10 minutes (or until manually stopped) to validate system behavior under load.

---

**The Store** - Built with ❤️ for modern e-commerce
