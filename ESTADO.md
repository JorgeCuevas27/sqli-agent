# Estado del proyecto (para retomar)

Agente multiagente de SQL injection, local (Ollama + qwen2.5:7b), que descubre el esquema por sí
mismo y evade WAFs. Mide time-to-exploit para comparar con un pentester humano.

## Qué funciona
- Descubrimiento de esquema en vivo (ORDER BY / UNION / information_schema), con verificación por
  etapas (error-based, boolean-based, fingerprint DBMS). No asume tablas/columnas.
- Evasión de WAF por gramática determinista (comentarios, case, etc.), alimentada de un dataset.
- Se alimenta de datasets reales: `datasets/corpus/` (781 payloads de PayloadsAllTheThings) +
  `datasets/sqli_kb.json` (plantillas + escalera de evasión).
- Runner de experimentos: `python -m src.experiments --runs N` -> CSV individual por corrida.

## Escenarios (docker-compose) y resultados reales
| Escenario | Puerto | WAF | Resultado del agente |
|---|---|---|---|
| sin-waf | :80 | — | ✅ 10/10 (low/med/high), ~1.1–1.3s |
| modsec-weak | :8083 | ModSecurity sin CRS (firmas) | ✅ 10/10, ~1.3–1.6s |
| naxsi | :8084 | NAXSI (scoring) | ✅ vencido con boolean-blind (LIKE) — ver abajo |

## HALLAZGO CLAVE — NAXSI es evadible con boolean-blind (probado empíricamente)
NAXSI bloquea `UNION`/`SELECT`/`substring`/`ascii`/`length`/`information_schema`, pero **DEJA PASAR**:
- el booleano puro: `1 AND 1=1` (true) vs `1 AND 1=2` (false)  -> confirma inyección
- `password LIKE 0x3525`  (prefijo, 0x25='%')  -> **200, devuelve fila si coincide**
- `password REGEXP 0x5e35` (^5) y `password RLIKE 0x35`  -> también pasan

=> El agente PUEDE vencer NAXSI con **extracción boolean-blind usando LIKE/REGEXP** (carácter por
carácter, con hex para evitar comillas), referenciando la columna directo (sin subquery SELECT).
Contexto numérico (DVWA medium) para evitar la comilla `'` (que NAXSI puntúa). NAXSI bloquea
information_schema, así que el nombre de columna se prueba con `AND <col> LIKE 0x25` (si da fila,
la columna existe).

## NAXSI: la evasión depende del CONTEXTO de inyección (hallazgo con evidencia)
Medido en vivo contra NAXSI :8084 nivel low (contexto cadena `WHERE user_id='$id'`):
```
PASA   200  '1'            <- numérico, sin comilla
BLOCK  403  "1'"           <- la comilla SOLA ya se bloquea
BLOCK  403  "1' AND 1=1-- -"
BLOCK  403  "1'='1"  / "1' OR '1'='1" / "1'||'1'='1"
```
NAXSI puntúa la comilla `'` por encima de su umbral, y en contexto de cadena la comilla es
OBLIGATORIA para inyectar → low y high son un TECHO para SQLi (ni el agente ni un humano pasan;
no hay forma estándar en MySQL de romper la cadena sin `'`; %27 se normaliza, `"` no rompe `'`).
En contexto NUMÉRICO (medium) no hace falta comilla → boolean-blind SÍ evade. Resultado para el
paper: **la efectividad de NAXSI depende del contexto** (numérico evadible, cadena infranqueable).

| NAXSI | contexto | agente |
|---|---|---|
| low | cadena (`'`) | ❌ techo (comilla bloqueada) |
| medium | numérico | ✅ bypass boolean-blind |
| high | cadena (`'`) | ❌ techo (esperado, mismo bloqueo) |

## Validado end-to-end (NAXSI vencido por el agente completo)
El fallback boolean-blind (`src/blind.py`, enganchado en el orquestador) ya corre dentro del agente:
contra NAXSI :8084 medium, UNION da 403 → el agente confirma inyección booleana → extrae con LIKE
`admin / 5f4dcc3b5aa765d61d8327deb882cf99` (498 sondeos, ~8.3s). El agente ELIGE la técnica según
el WAF (UNION cuando pasa; boolean-blind cuando UNION está bloqueado pero el booleano entra).

## Próximo paso (pendiente)
Re-correr el sweep completo de experimentos ahora que NAXSI es vencible, para el CSV final con los
4 escenarios x niveles (individual por corrida). Luego: tablas/gráficos del paper + baseline humano.

## Cómo retomar
Abrir el proyecto y leer este archivo. El código está todo en el repo; los experimentos se corren
con `OLLAMA_URL=http://192.168.56.1:11434 python -m src.experiments --runs 10`.
