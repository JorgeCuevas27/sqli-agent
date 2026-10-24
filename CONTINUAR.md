# Continuar el proyecto en otra PC

Herramienta multiagente (Planner + Executor + Analyst + orquestador) en Python que explota SQL Injection en DVWA usando un LLM local (Ollama). Es el sistema "propuesto" de un artículo de investigación; PentAGI es el baseline de comparación.

## Estado actual (2026-10-11)

Nivel **low: funciona de punta a punta** — extrae los 5 hashes de la tabla `users`, SUCCESS en el paso 1, ~460 s en CPU (la lentitud es el hardware, no el método).

Pendiente: niveles **medium** y **high**, un **script de experimentos** (N corridas por nivel + tiempos promedio para las tablas del paper), y pasar a **GPU** (PC nueva con RTX 5070 12GB).

Hipótesis / métrica del paper: tiempo hasta la explotación (time-to-exploit) frente a los ~10 min de un pentester humano.

## Cómo está montado

Cerebro: **Ollama**, modelo `qwen2.5:7b`, local (en la RTX 5070 caben también `qwen2.5:14b` Q4).

Objetivo: **DVWA** (contenedor `vulnerables/web-dvwa`) en una VM de Kali, IP host-only `192.168.56.101`.

`src/config.py` apunta DVWA y Ollama a `192.168.56.101`; cambiar ahí si la IP/URL es distinta en la PC nueva (por variable de entorno `DVWA_URL` / `OLLAMA_URL` o editando el archivo).

## Cómo ejecutar

Dependencias: `pip install -r requirements.txt`

Agente completo (los 3 agentes): `python -m src.main --level low`

Extracción rápida sin IA (solo el cliente DVWA): `python dump_creds.py`

Cada corrida del agente guarda un JSON en `results/` con tiempo, pasos, payloads y credenciales.

## Archivos clave

`src/orchestrator.py` — bucle coordinador + detección determinista de éxito (`_credential_rows` reconoce hashes).

`src/dvwa.py` — herramienta DVWA: login, fija nivel, envía payload, parsea resultados (maneja low/medium/high).

`src/agents/` + `src/prompts/` — los 3 agentes y sus prompts editables.

`src/main.py` — CLI. `dump_creds.py` — dump rápido. `docker-compose.yml` — DVWA en el host (alternativa a la VM).

## Siguientes pasos en la PC nueva (RTX 5070 12GB)

1. Instalar **Ollama para Windows** (detecta la GPU NVIDIA automáticamente) y `ollama pull qwen2.5:7b`.
2. Clonar este repo y `pip install -r requirements.txt`.
3. Levantar DVWA (en la VM de Kali, o `docker compose up -d` en local) y ajustar `src/config.py`.
4. Confirmar nivel **low**, luego implementar/afinar **medium** y **high**.
5. Crear el **script de experimentos** (N corridas por nivel + promedios) para las tablas del paper.
