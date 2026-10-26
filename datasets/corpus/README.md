# Corpus de payloads SQLi (real)

Payloads de inyección SQL **reales**, descargados de **PayloadsAllTheThings**
(https://github.com/swisskyrepo/PayloadsAllTheThings, carpeta `SQL Injection/Intruder`).
Uso educativo / de investigación.

El agente los carga vía `src/knowledge.py` como base de conocimiento, agrupados por técnica según
el nombre del archivo.

| Archivo | Técnica | Payloads |
|---|---|---|
| `Generic_UnionSelect.txt` | union | 424 |
| `Generic_ErrorBased.txt` | error-based | 154 |
| `Generic_TimeBased.txt` | time-based | 105 |
| `patt_auth_bypass.txt` (`Auth_Bypass.txt`) | boolean/auth-bypass | 78 |
| `Generic_Fuzz.txt` | detección | 11 |
| `FUZZDB_MYSQL.txt` | MySQL | 6 |
| `SQLi_Polyglots.txt` | detección (polyglot) | 2 |

Para citar en la tesis: *"se utilizó el corpus público de payloads SQLi de PayloadsAllTheThings
(swisskyrepo), agrupado por técnica"*.

> Nota: estos archivos son datos externos (payloads). El agente los usa como contenido a enviar,
> nunca como código ejecutable.
