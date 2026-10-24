# sqli-agent

Agente multiagente que explota SQL Injection de forma automática sobre DVWA, usando un modelo de lenguaje local con Ollama. Es para un trabajo de investigación.

Uso educativo, solo contra DVWA en local.

## Requisitos

- Python 3.12
- Docker
- Ollama con el modelo `qwen2.5:7b`

## Uso

```
pip install -r requirements.txt
docker-compose up -d
python -m src.main --level low
```
