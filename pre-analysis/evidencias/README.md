# `evidencias/` — Datos crudos de la auditoría pre-WAF

Evidencia de que los 10-16 vectores documentados en el [README maestro](../README.md) son explotables en el estado actual de The Store (sin WAF). Capturado en vivo el 16-abr-2026 contra `http://localhost` desde la consola del navegador.

## Inventario

| Archivo | Tamaño | Formato | Contenido | Cuándo usarlo |
|---|---|---|---|---|
| **`raw-http-transcripts.txt`** | 12 KB | texto plano anotado | 10 PoCs con request + response + veredicto + análisis | Slide base del PPT — lo más legible para mostrar |
| **`pocs-data.json`** | 4,7 KB | JSON estructurado | Metadata de cada PoC: severidad, mapeo OWASP Top 10 2025, regla CRS que mitiga | Entrada de scripts comparativos antes/después |
| **`full-raw-bundle.txt`** | 149 KB | texto plano raw | 16 PoCs con responses completas (no truncadas) — dump crudo de la sesión | Anexo técnico si la cátedra pide ver todo sin edición |
| **`full-raw-bundle.json`** | 153 KB | JSON estructurado | Misma data que el bundle.txt pero machine-readable, con headers y bodies completos | Análisis programático, generación de reportes derivados |

## Cuál usar según el contexto

- **Para el PDF de pre-entrega (21/04):** `raw-http-transcripts.txt` — tiene los veredictos y análisis listos para citar.
- **Para el PPT de la demo final (9/6):** `raw-http-transcripts.txt` como base de los slides "antes" + `pocs-data.json` para generar la tabla comparativa post-WAF.
- **Para el how-to de GitHub:** ambos — el curado va al body del how-to, el raw queda como evidencia adjunta.
- **Para auditoría interna del grupo:** los 4, sumados al [`../demo/exploit-dashboard.html`](../demo/exploit-dashboard.html) para re-ejecutar.

## Cómo regenerar esta evidencia

### Desde la terminal (curl)

```bash
cd ../../..   # volver a la raíz del repo
./local.sh create-cluster --skip-tests   # si el cluster no está arriba
bash pre-analysis/tests/01-pre-waf-attacks.sh 2>&1 | tee pre-analysis/evidencias/resultados-pre-waf-$(date +%F).txt
```

### Desde el navegador (dashboard interactivo)

```bash
open pre-analysis/demo/exploit-dashboard.html      # macOS
xdg-open pre-analysis/demo/exploit-dashboard.html  # Linux
```

Click en **"Run All Exploits"**, después en **"📋 Copy Markdown report"** o **"📋 Export JSON"**. El JSON se descarga a `~/Downloads/`.

## Cómo generar la data post-WAF para el diff

Una vez desplegado ModSecurity + OWASP CRS (sección 7 del README maestro):

1. Correr el dashboard de nuevo contra el mismo target.
2. Exportar JSON → renombrar a `pocs-data-post-waf.json` y guardar en este directorio.
3. Comparar:

```bash
diff <(jq -c '.results[] | {id,status,verdict}' pocs-data.json | sort) \
     <(jq -c '.results[] | {id,status,verdict}' pocs-data-post-waf.json | sort)
```

Resultado esperado: todos los `status:200` del pre se vuelven `status:403` en el post, y los `verdict:"vuln"` pasan a `verdict:"blocked"`.

## Capturas de pantalla

Las capturas que tomé durante la auditoría quedaron en la carpeta Downloads de la Mac del expositor — intentamos automatizar el guardado pero la API del plugin del navegador no devolvía path consistente. Para la presentación final recomendamos:

1. Re-correr la demo justo antes del 9/6 y tomar capturas manualmente con `Cmd+Shift+4` o `Cmd+Shift+5`.
2. Guardarlas en un subfolder `capturas/` dentro de este mismo directorio.
3. Mejor alternativa aún: el [`../demo/evidence-pack.html`](../demo/evidence-pack.html) es un "screenshot equivalente" auto-contenido que muestra cada PoC con request+response formateados como reporte forense — abre en cualquier navegador sin dependencias y queda como pieza visual de respaldo independiente de las capturas reales.
