"""
ATENÇÃO — ROTAS INTENCIONALMENTE VULNERÁVEIS
==============================================
Rotas de Produtos. Uso didático (trabalho sobre OWASP API
Security Top 10). NÃO utilize em produção.
"""

from typing import List

from fastapi import APIRouter, Depends, Query

from controllers.ProductController import ProductController
from limits import (
    DEFAULT_PAGE_SIZE,
    MAX_OFFSET,
    MAX_PAGE_SIZE,
    MAX_PRODUCT_PRICE,
    enforce_rate_limit,
)
from models.ProductModel import PublicProductModel
from security import CurrentUser, require_admin

router = APIRouter(prefix="", tags=["Produtos"])


@router.get(
    "/products",
    response_model=List[PublicProductModel],
    dependencies=[Depends(enforce_rate_limit)],
)
async def get_products(
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(0, ge=0, le=MAX_OFFSET),
):
    """
    API4:2023 - Unrestricted Resource Consumption
    --------------------------------------------------
    A rota usa paginação com limite padrão e máximo definidos no servidor.
    O rate limiting também impede chamadas repetitivas sem controle.

    API3:2023 - Excessive Data Exposure
    --------------------------------------------------
    A resposta contém somente os campos públicos do catálogo; custos e
    notas internas não são serializados.
    """
    return ProductController.get_products(limit=limit, offset=offset)


@router.get(
    "/products/search",
    dependencies=[Depends(enforce_rate_limit)],
)
async def search_products(
    name: str = Query(..., min_length=1, max_length=100),
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(0, ge=0, le=MAX_OFFSET),
):
    """
    Hardening contra Injection (SQL Injection)
    --------------------------------------------------
    `name` é validado pela rota e enviado ao controlador como parâmetro
    preparado; payloads como `' OR '1'='1` não alteram a consulta SQL.

    API3:2023 - Excessive Data Exposure
    --------------------------------------------------
    Mesmo com a falha de SQL Injection ainda presente, a consulta e a
    resposta limitam-se às colunas públicas do produto.

    API8:2023 - Security Misconfiguration
    --------------------------------------------------
    O tratamento de erro detalhado ainda é um cenário didático pendente
    de API8 e não deve ser usado em produção.
    """
    return ProductController.search_products(name, limit=limit, offset=offset)


@router.delete("/products/{product_id}")
async def delete_product(
    product_id: int,
    current_user: CurrentUser = Depends(require_admin),
):
    """
    API5:2023 - Broken Function Level Authorization
    --------------------------------------------------
    Operação administrativa protegida por autenticação e pela função
    de administrador antes de chegar ao controlador.
    """
    return ProductController.delete_product(product_id, current_user)


@router.put("/products/{product_id}/price")
async def update_price(
    product_id: int,
    new_price: float = Query(..., gt=0, le=MAX_PRODUCT_PRICE),
    current_user: CurrentUser = Depends(require_admin),
):
    """
    API5:2023 - Broken Function Level Authorization
    API6:2023 - Unrestricted Access to Sensitive Business Flows
    --------------------------------------------------
    A operação exige função administrativa e aceita somente preços
    positivos dentro do limite definido pelo servidor. A alteração é
    registrada pelo controlador para auditoria operacional.
    """
    return ProductController.update_price(product_id, new_price, current_user)
