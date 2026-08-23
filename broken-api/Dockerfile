# Use uma versão do Python que possua vulnerabilidades conhecidas no SO
# para que o 'Trivy' ou 'Snyk' encontre falhas na etapa de Container Scan
FROM python:3.12-alpine

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py run.py users_db.py ./
COPY controllers ./controllers
COPY models ./models
COPY routes ./routes
COPY tests ./tests

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
