"""
ATENÇÃO — API INTENCIONALMENTE VULNERÁVEL
==============================================
Este arquivo apenas monta a aplicação FastAPI e registra as rotas,
que agora estão organizadas por domínio dentro da pasta `routes/`:
  - routes/auth_routes.py       -> Autenticação
  - routes/checkout_routes.py   -> Checkout
  - routes/product_routes.py    -> Produtos
  - routes/user_routes.py       -> Usuários

Uso didático (trabalho sobre OWASP API Security Top 10 - 2023).
NÃO utilize esta configuração em produção.

Nota importante sobre a causa-raiz comum a várias rotas:
--------------------------------------------------------------
A dependência `get_current_user`, em `security.py`, valida um JWT assinado
e resolve a identidade no servidor. Os controles compartilhados de limite,
em `limits.py`, protegem os endpoints de maior consumo contra requisições
e respostas sem limite. As demais vulnerabilidades do laboratório continuam
presentes de forma intencional até suas etapas específicas de mitigação.
"""

import logging
import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from config import docs_are_enabled, is_production_environment
from controllers.IntegrationController import validate_integration_config
from controllers.ProductController import ProductController
from controllers.SecurityStatusController import validate_owasp_status_config
from limits import MAX_REQUEST_BODY_BYTES, RequestBodySizeLimitMiddleware
from routes.AuthRoutes import router as auth_router
from routes.CheckoutRoutes import router as checkout_router
from routes.IntegrationRoutes import router as integration_router
from routes.ProductRoutes import router as product_router
from routes.SecurityRoutes import router as security_router
from routes.UserRoutes import router as user_router
from security import validate_security_config
from security_headers import SecurityHeadersMiddleware


logger = logging.getLogger(__name__)
APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
DOCS_ENABLED = docs_are_enabled(APP_ENV, os.getenv("API_DOCS_ENABLED"))
IS_PRODUCTION = is_production_environment(APP_ENV)

app = FastAPI(
    title="API Vulnerável (uso didático)",
    # API8:2023 - Security Misconfiguration
    # O contrato fica disponível no laboratório/CI para permitir o DAST,
    # mas é removido completamente em produção.
    docs_url="/docs" if DOCS_ENABLED else None,
    redoc_url="/redoc" if DOCS_ENABLED else None,
    openapi_url="/openapi.json" if DOCS_ENABLED else None,
)

app.add_middleware(
    RequestBodySizeLimitMiddleware,
    max_body_bytes=MAX_REQUEST_BODY_BYTES,
)
app.add_middleware(SecurityHeadersMiddleware, production=IS_PRODUCTION)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Registra detalhes somente no servidor e usa resposta pública genérica."""

    logger.exception(
        "unhandled_application_error method=%s path=%s",
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


@app.on_event("startup")
def startup():
    validate_security_config()
    validate_integration_config()
    validate_owasp_status_config()
    ProductController.initialize_database()


app.include_router(auth_router)
app.include_router(checkout_router)
app.include_router(integration_router)
app.include_router(product_router)
app.include_router(security_router)
app.include_router(user_router)
