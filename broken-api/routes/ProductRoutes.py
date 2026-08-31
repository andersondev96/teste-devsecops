"""
ATENÇÃO — ROTAS INTENCIONALMENTE VULNERÁVEIS
==============================================
Rotas de Produtos. Uso didático (trabalho sobre OWASP API
Security Top 10). NÃO utilize em produção.
"""

from typing import List

from fastapi import APIRouter

from controllers.ProductController import ProductController
from models.ProductModel import PublicProductModel

router = APIRouter(prefix="", tags=["Produtos"])


@router.get("/products", response_model=List[PublicProductModel])
async def get_products():
    """
    API4:2023 - Unrestricted Resource Consumption
    --------------------------------------------------
    Sem paginação/LIMIT: resposta cresce sem controle conforme a
    tabela cresce, permitindo esgotamento de recursos do servidor.

    API3:2023 - Excessive Data Exposure
    --------------------------------------------------
    A resposta contém somente os campos públicos do catálogo; custos e
    notas internas não são serializados.
    """
    return ProductController.get_products()


@router.get("/products/search")
async def search_products(name: str):
    """
    Injection (SQL Injection)
    --------------------------------------------------
    `name` é concatenado diretamente na query SQL, sem parâmetros
    preparados -> permite extrair ou manipular dados do banco via
    payloads como `' OR '1'='1` ou `' UNION SELECT ...`.

    API3:2023 - Excessive Data Exposure
    --------------------------------------------------
    Mesmo com a falha de SQL Injection ainda presente, a consulta e a
    resposta limitam-se às colunas públicas do produto.

    API8:2023 - Security Misconfiguration
    --------------------------------------------------
    Em caso de erro, a rota devolve a query executada e o stack trace
    completo na resposta, ajudando o atacante a refinar o ataque.
    """
    return ProductController.search_products(name)


@router.delete("/products/{product_id}")
async def delete_product(product_id: int):
    """
    API5:2023 - Broken Function Level Authorization
    --------------------------------------------------
    Operação administrativa (excluir produto) exposta sem checagem
    de papel/permissão -> qualquer chamador apaga qualquer produto.
    """
    return ProductController.delete_product(product_id)


@router.put("/products/{product_id}/price")
async def update_price(product_id: int, new_price: float):
    """
    API5:2023 - Broken Function Level Authorization
    API6:2023 - Unrestricted Access to Sensitive Business Flows
    --------------------------------------------------
    Qualquer chamador altera o preço de qualquer produto, sem
    autenticação, sem validação de faixa (aceita valores negativos)
    e sem log de auditoria.
    """
    return ProductController.update_price(product_id, new_price)
