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
| naxsi | :8084 | NAXSI (scoring) | ❌ techo con UNION (ver abajo) |
| crs | :8081 | ModSecurity + OWASP CRS (libinjection) | ❌ techo (consistente con la literatura) |

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

## Próximo paso (pendiente)
Implementar un módulo de **extracción boolean-blind** (LIKE) y que el agente **elija la técnica
según el WAF**: UNION cuando pasa; boolean-blind cuando el WAF bloquea UNION pero deja booleanos
(NAXSI). Con eso NAXSI pasa de "techo" a "evadido". Luego: re-correr experimentos y armar tablas.

## Cómo retomar
Abrir el proyecto y leer este archivo. El código está todo en el repo; los experimentos se corren
con `OLLAMA_URL=http://192.168.56.1:11434 python -m src.experiments --runs 10`.
