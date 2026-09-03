# Use uma versão do Python que possua vulnerabilidades conhecidas no SO
# para que o 'Trivy' ou 'Snyk' encontre falhas na etapa de Container Scan
FROM python:3.12-alpine

WORKDIR /app

COPY requirements.txt .
RUN apk upgrade --no-cache \
    && python -m pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY main.py run.py security.py users_db.py limits.py ./
COPY owasp_status.json ./owasp_status.json
COPY controllers ./controllers
COPY models ./models
COPY routes ./routes
COPY tests ./tests

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
