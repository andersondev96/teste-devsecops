# Use uma versão do Python que possua vulnerabilidades conhecidas no SO
# para que o 'Trivy' ou 'Snyk' encontre falhas na etapa de Container Scan
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]