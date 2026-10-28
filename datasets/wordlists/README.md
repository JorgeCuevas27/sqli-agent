# Wordlists de nombres comunes (sqlmap)

Listas **reales** de nombres comunes de columnas y tablas, descargadas de **sqlmap**
(https://github.com/sqlmapproject/sqlmap/tree/master/data/txt). Uso educativo / de investigación.

| Archivo | Origen en sqlmap | Entradas | Para qué |
|---|---|---|---|
| `common-columns.txt` | `data/txt/common-columns.txt` | ~2.8k | adivinar nombres de columnas cuando `information_schema` está bloqueado |
| `common-tables.txt` | `data/txt/common-tables.txt` | ~3.4k | adivinar nombres de tablas cuando no se puede enumerar |

Son exactamente las wordlists que usa sqlmap en sus modos `--common-columns` / `--common-tables`,
pensados para el caso en que el WAF (p. ej. NAXSI) bloquea `information_schema`. El agente las carga
vía `src/knowledge.py` y las usa en la ruta de descubrimiento ciego (`src/blind.py`): prueba primero
los nombres con pinta de credencial y confirma su existencia con un sondeo `LIKE` por columna.

Para citar en la tesis: *"para el descubrimiento de columnas/tablas sin `information_schema` se
utilizaron las wordlists públicas de sqlmap (common-columns, common-tables)"*.

> Nota: datos externos (nombres), nunca código ejecutable. Las dos primeras líneas de cada archivo
> son el encabezado de copyright de sqlmap y se ignoran al cargar.
