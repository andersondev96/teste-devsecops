"""
ATENCAO - ROTAS INTENCIONALMENTE VULNERAVEIS
============================================
Rotas de integracoes externas usadas no laboratorio OWASP API Top 10
2023. NAO utilize em producao.
"""

from fastapi import APIRouter

from controllers.IntegrationController import IntegrationController

router = APIRouter(prefix="/integrations", tags=["Integracoes inseguras"])


@router.get("/fetch-url")
async def fetch_url(url: str):
    """
    API7:2023 - Server Side Request Forgery (SSRF)
    --------------------------------------------------
    O servidor busca qualquer URL enviada pelo cliente, inclusive hosts
    internos e metadata services de nuvem.
    """
    return IntegrationController.fetch_remote_url(url)


@router.get("/address/enrich")
async def enrich_address(zipcode: str, provider_url: str):
    """
    API10:2023 - Unsafe Consumption of APIs
    --------------------------------------------------
    A API consome um provedor externo informado pelo cliente e confia
    integralmente no JSON recebido, sem validar contrato ou origem.
    """
    return IntegrationController.enrich_address(zipcode, provider_url)
