# Imagem base com versão de Python e família do Alpine explicitamente definidas.
# Atualizações de patch devem ser feitas de forma intencional e validadas pelo
# scan de imagem do pipeline.
FROM python:3.12.14-alpine3.24@sha256:b64631e04e4920160c50fbe8d8df828f7f35f06f425cb44aa09bca53e708a35a

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# O processo não precisa de privilégios administrativos em runtime. O diretório
# /app permanece gravável porque a aplicação cria o SQLite do laboratório no
# startup; os arquivos instalados fora dele continuam pertencendo ao root.
RUN addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -G app app \
    && chown app:app /app

COPY requirements.txt .
# Atualiza as ferramentas usadas somente durante o build. Elas são removidas
# ao final para que pip/setuptools e seus módulos vendorizados não façam parte
# do runtime da API.
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt \
    && python -m pip install --no-cache-dir \
        "setuptools==83.0.0" \
    && rm -rf \
        /usr/local/lib/python3.12/site-packages/pip \
        /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
        /usr/local/lib/python3.12/site-packages/setuptools \
        /usr/local/lib/python3.12/site-packages/setuptools-*.dist-info \
        /usr/local/bin/pip \
        /usr/local/bin/pip3 \
        /usr/local/bin/pip3.12

# O código é copiado como root e fica somente para leitura pelo usuário de
# runtime; somente o diretório /app precisa aceitar o SQLite do laboratório.
COPY main.py run.py security.py users_db.py limits.py config.py security_headers.py ./
COPY owasp_status.json ./owasp_status.json
COPY controllers ./controllers
COPY models ./models
COPY routes ./routes

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; response = urllib.request.urlopen('http://127.0.0.1:8000/security/owasp', timeout=2); raise SystemExit(0 if response.status == 200 else 1)"]

# Uvicorn e a API executam com UID sem privilégios.
USER app

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
