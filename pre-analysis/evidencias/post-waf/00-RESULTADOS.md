# Resultados antes/después · WAF sobre The Store

Corrida end-to-end real sobre el cluster Kind local. Baseline pre-WAF y
verificación post-WAF capturados el mismo día contra `http://localhost`.

- Baseline pre-WAF: [`00-baseline-pre-waf-*.txt`](.)
- Resultados post-WAF: [`01-resultados-post-waf-*.txt`](.)
- Audit log de ModSecurity: [`02-modsec_audit.log.txt`](02-modsec_audit.log.txt)
- Headers post-WAF: [`03-headers-post-waf.txt`](03-headers-post-waf.txt)

## Tabla comparativa (los 5 casos de la pre-entrega)

| # | Caso | Pre-WAF | Post-WAF | Regla que bloqueó |
|---|------|---------|----------|-------------------|
| 1 | `GET /actuator/prometheus` | `200 OK` · 18.990 bytes filtrados | **`403`** | custom `99001` |
| 2 | Path traversal `/proxy/catalog/../../actuator/info` | `200 OK` | **`403`** | custom `99002` |
| 3 | `User-Agent: Nikto/2.5` (y sqlmap, nuclei) | `200 OK` | **`403`** | custom `99010` |
| 4 | Burst de 100 requests concurrentes a `/` | 100/100 → `200` | **23/100 → `429`** | nginx `limit_req` (10 rps) |
| 5 | Headers de seguridad en la home | 0/6 presentes | **6/6 presentes** | annotation `more_set_headers` |

Los 5 casos comprometidos en la pre-entrega pasan de vulnerable a mitigado.

## Resultado de la suite automatizada

```
RESUMEN · TESTS POST-WAF
  Pasaron:  23 / 23
  Fallaron: 0 / 23
```

## Defensa en profundidad: reglas custom + OWASP CRS

El audit log demuestra que las reglas propias y el Core Rule Set actúan juntos:

| Origen | Regla | Qué cazó |
|--------|-------|----------|
| Custom | `99001` | `/actuator/{info,metrics,prometheus,env}` |
| Custom | `99002` | path traversal `..` / `%2e%2e` sobre `/proxy/*` |
| Custom | `99003` | `/proxy/<svc>/actuator` (ruta admin vía proxy) |
| Custom | `99010` | User-Agents de sqlmap / nikto / nuclei |
| OWASP CRS | `941100/110/160/390` | XSS (libinjection + filtros) en el checkout |
| OWASP CRS | `942100/350` | SQL injection (libinjection) en el checkout |
| OWASP CRS | `949110` | Anomaly score excedido (suma de scores parciales) |

Los casos de XSS/SQLi (H2) NO necesitaron reglas custom: el CRS base los cubre.
Esto valida la decisión de diseño de la pre-entrega: CRS para ataques genéricos
de capa 7 + reglas custom para la lógica específica de The Store.

## /actuator/health se preserva

`GET /actuator/health` sigue devolviendo `200 OK` después del WAF (regla 99001
excluye explícitamente `health`). Esto es crítico: Kubernetes usa ese endpoint
para los readiness/liveness probes; bloquearlo tumbaría el pod del UI.
