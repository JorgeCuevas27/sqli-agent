# Laboratorio para pruebas manuales

Monta los 4 escenarios (el mismo DVWA detrás de distintos WAFs) en una Kali para atacarlos a mano.
No hace falta Ollama, Python ni el agente — **solo Docker**. Todo está en `docker-compose.yml`.

## 1. Requisitos (en Kali)

```
sudo apt update
sudo apt -y install git docker.io docker-compose
sudo systemctl enable --now docker
```

## 2. Clonar y levantar el laboratorio

```
git clone https://github.com/JorgeCuevas27/sqli-agent.git
cd sqli-agent
sudo docker-compose up -d --build
```

La primera vez descarga las imágenes y construye los WAFs (unos minutos). Verifica que estén arriba:

```
sudo docker-compose ps
```

Deben aparecer como `Up`: `sqli-dvwa`, `sqli-naive-waf`, `sqli-modsec-weak`, `sqli-waf`.

## 3. Inicializar DVWA (una sola vez)

Abre `http://localhost` → login **admin** / **password** → botón **Create / Reset Database**.

## 4. Los 4 escenarios (mismo DVWA, distinto WAF)

| Escenario | URL para atacar | Dificultad |
|---|---|---|
| Sin WAF | http://localhost | ninguna |
| ModSecurity sin CRS | http://localhost:8083 | baja (se evade con comentarios) |
| NAXSI (nginx) | http://localhost:8084 | media (WAF por scoring) |
| ModSecurity + OWASP CRS | http://localhost:8081 | alta (libinjection) |

Para cada escenario, haz la inyección SQL **manualmente** (navegador o Burp Suite) contra esa URL.

## 5. Nivel de seguridad de DVWA (low / medium / high)

Dentro de DVWA → pestaña **DVWA Security** → elige el nivel → Submit. Luego ve a **SQL Injection**
y ataca. El nivel se guarda en la sesión del navegador.

## 6. Qué esperar

- **Sin WAF**: los payloads clásicos funcionan directo (`1' UNION SELECT user,password FROM users-- -`).
- **ModSecurity sin CRS**: bloquea el SQLi plano, pero se **evade con comentarios**
  (`1'/**/UNION/**/SELECT/**/user,password/**/FROM/**/users-- -`) o `UNION ALL`.
- **NAXSI**: WAF por scoring (suma puntos por tokens sospechosos); bloquea el SQLi plano y es
  resistente a los comentarios (que suman puntaje). Escenario intermedio.
- **ModSecurity + CRS**: bloquea casi todo (comentarios y mayúsculas no sirven contra libinjection);
  el escenario más difícil.

## 7. Medición (línea base humana)

Cronometra cuánto tardas en resolver cada escenario a mano, por nivel de DVWA. Ese tiempo es la
**línea base humana** del estudio, contra la que se compara el agente automático.
