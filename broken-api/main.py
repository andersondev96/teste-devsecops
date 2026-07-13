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
Esta API NÃO possui nenhum middleware/dependência real de autenticação
(nada equivalente a `Depends(get_current_user)` validando um JWT).
Isso é, por si só, uma instância de **API2:2023 - Broken Authentication**
que se propaga por quase todas as rotas: qualquer "identidade" usada
(como `current_user_id`) vem diretamente de um parâmetro que o PRÓPRIO
CLIENTE informa na requisição — ou seja, o cliente pode se
autodeclarar como qualquer usuário, inclusive admin, sem nenhuma prova
de identidade. Isso é o que transforma quase todo BOLA (API1)
documentado nos controllers em uma falha explorável de fato.
"""

from fastapi import FastAPI

from controllers.ProductController import ProductController
from routes.AuthRoutes import router as auth_router
from routes.CheckoutRoutes import router as checkout_router
from routes.ProductRoutes import router as product_router
from routes.UserRoutes import router as user_router

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
    ProductController.initialize_database()


app.include_router(auth_router)
app.include_router(checkout_router)
app.include_router(product_router)
app.include_router(user_router)