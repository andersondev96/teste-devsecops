"""
Rotas de integrações externas usadas no laboratório OWASP API Top 10 2023.
O endpoint de SSRF (API7) permanece didático; o enriquecimento de endereço
aplica os controles de consumo seguro da API10.
"""

from fastapi import APIRouter, Query

from controllers.IntegrationController import IntegrationController
from models.IntegrationModel import AddressEnrichmentResponseModel

router = APIRouter(prefix="/integrations", tags=["Integrações externas"])


@router.get("/fetch-url")
async def fetch_url(url: str):
    """
    API7:2023 - Server Side Request Forgery (SSRF)
    --------------------------------------------------
    O servidor busca qualquer URL enviada pelo cliente, inclusive hosts
    internos e metadata services de nuvem.
    """
    return IntegrationController.fetch_remote_url(url)


@router.get("/address/enrich", response_model=AddressEnrichmentResponseModel)
async def enrich_address(
    zipcode: str = Query(..., min_length=8, max_length=9, pattern=r"^\d{8}(-\d{1,3})?$"),
):
    """
    API10:2023 - Unsafe Consumption of APIs
    --------------------------------------------------
    A API usa um provedor HTTPS fixo em allowlist. O contrato da resposta
    externa é validado antes de qualquer decisão local e o payload bruto
    não é devolvido ao cliente.
    """
    return IntegrationController.enrich_address(zipcode)
