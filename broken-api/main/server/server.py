import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from main.server.api import api_router

# Configuração de Logging Segura
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Secured API Final", version="1.4")

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    # Impede que o navegador adivinhe o Content-Type (Protege contra MIME Sniffing)
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Impede Clickjacking (não deixa o site ser carregado dentro de um iFrame)
    response.headers["X-Frame-Options"] = "DENY"
    # Proteção básica contra XSS no navegador
    response.headers["X-XSS-Protection"] = "1; mode=block"
    # Define política de origem cruzada rígida
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    # Força a comunicação por HTTPS
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Em produção, defina o domínio específico do seu frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Tratamento para exceções específicas da API
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    logger.error(f"Erro HTTP: {exc.detail}")
    return JSONResponse(status_code=exc.status_code, content={"message": exc.detail})

app.include_router(api_router, prefix="/api/v1")