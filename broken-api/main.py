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
A dependência `get_current_user`, em `security.py`, agora valida um JWT
assinado e resolve a identidade no servidor. Ela será aplicada às rotas
de negócio durante a mitigação da API1. As rotas que ainda recebem
`current_user_id` ou não usam essa dependência continuam vulneráveis de
forma intencional até essa próxima etapa.
"""

from fastapi import FastAPI

from controllers.ProductController import ProductController
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


@app.on_event("startup")
def startup():
    validate_security_config()
    ProductController.initialize_database()


app.include_router(auth_router)
app.include_router(checkout_router)
app.include_router(integration_router)
app.include_router(product_router)
app.include_router(user_router)
