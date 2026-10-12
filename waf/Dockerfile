FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.0.3 requests==2.32.3
WORKDIR /app
COPY rules.py naive_waf.py /app/
ENV BACKEND=http://dvwa:80 PORT=8082
EXPOSE 8082
CMD ["python", "naive_waf.py"]
