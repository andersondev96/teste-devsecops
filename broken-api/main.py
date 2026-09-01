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

from fastapi import FastAPI

from controllers.ProductController import ProductController
from limits import MAX_REQUEST_BODY_BYTES, RequestBodySizeLimitMiddleware
from routes.AuthRoutes import router as auth_router
from routes.CheckoutRoutes import router as checkout_router
from routes.IntegrationRoutes import router as integration_router
from routes.ProductRoutes import router as product_router
from routes.UserRoutes import router as user_router
from security import validate_security_config

app = FastAPI(
    title="API Vulnerável (uso didático)",
    # API8:2023 - Security Misconfiguration
    # docs_url/redoc_url deixados abertos por padrão em qualquer
    # ambiente (inclusive "produção"), expondo publicamente todo o
    # contrato da API (rotas, parâmetros, modelos) para reconhecimento
    # de um atacante. Em produção deveriam ser desabilitados ou
    # protegidos por autenticação.
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    RequestBodySizeLimitMiddleware,
    max_body_bytes=MAX_REQUEST_BODY_BYTES,
)


@app.on_event("startup")
def startup():
    validate_security_config()
    ProductController.initialize_database()


app.include_router(auth_router)
app.include_router(checkout_router)
app.include_router(integration_router)
app.include_router(product_router)
app.include_router(user_router)
