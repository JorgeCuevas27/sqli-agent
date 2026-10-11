# SQLi-Agent — Agente multiagente para SQL Injection sobre DVWA

Sistema **local** de agentes de IA (LLM vía **Ollama**, modelo `qwen2.5:7b`) que automatiza la
explotación de **SQL Injection** contra **DVWA** en sus niveles de seguridad *low*, *medium* y *high*.

Proyecto de investigación. Se ejecuta **solo contra DVWA en local** (aplicación deliberadamente
vulnerable, propia, para fines educativos/investigación). **No usar contra sistemas de terceros.**

## Idea de investigación

- **Pregunta:** ¿puede un agente LLM local resolver SQLi en DVWA (todos los niveles) en **menos tiempo**
  que el promedio de un pentester humano (~10 min)?
- **Métrica:** tasa de éxito por nivel + **tiempo hasta la explotación** (time-to-exploit).
- **Baseline de comparación:** PentAGI (plataforma general de 15 agentes). Este proyecto es la
  propuesta "lean": 3 agentes especializados en SQLi.

## Arquitectura (3 agentes + orquestador)

```
Objetivo (nivel DVWA)
        │
        ▼
  Orchestrator  ── coordina el bucle y mide el tiempo
        │
        ├─ Planner   → analiza el nivel y decide la estrategia SQLi (payloads a probar)
        ├─ Executor  → login en DVWA, maneja cookie de seguridad + token CSRF, envía payloads HTTP
        └─ Analyst   → inspecciona respuestas, confirma inyección, extrae datos, decide si seguir
```

Correspondencia con PentAGI (para el paper): Planner ≈ `primary_agent`+`generator`+`refiner`;
Executor ≈ `pentester`+`coder`+herramientas; Analyst ≈ `reflector`+`reporter`.

## Requisitos

- Docker Desktop (para DVWA).
- Ollama con el modelo `qwen2.5:7b` (ya instalado en el otro proyecto; lo reutilizamos).
- Python 3.12+.

## Puesta en marcha (resumen — se irá completando)

```bash
# 1. Levantar el objetivo (DVWA) y Ollama
docker compose up -d

# 2. Dependencias de Python
pip install -r requirements.txt

# 3. Primera vez en DVWA: http://localhost:8080  (admin/password) -> "Create / Reset Database"

# 4. Ejecutar el agente (cuando esté implementado)
python -m src.main --level low
```

## Estado

- [x] Hito 0 — Esqueleto del proyecto + entorno (DVWA + Ollama local)
- [ ] Hito 1 — Executor: login en DVWA + acceso a la página de SQLi (plumbing)
- [ ] Hito 2 — Bucle de 3 agentes resolviendo SQLi nivel *low* con medición de tiempo
- [ ] Hito 3 — Niveles *medium* y *high*
- [ ] Hito 4 — Métricas y reporte para el paper
