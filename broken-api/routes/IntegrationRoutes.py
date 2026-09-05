"""Rotas de integrações externas usadas no laboratório OWASP API Top 10 2023."""

from fastapi import APIRouter, Depends, Query

from controllers.IntegrationController import IntegrationController
from limits import enforce_rate_limit
from models.IntegrationModel import (
    AddressEnrichmentResponseModel,
    RemoteFetchResponseModel,
)

router = APIRouter(prefix="/integrations", tags=["Integrações externas"])


@router.get(
    "/fetch-url",
    response_model=RemoteFetchResponseModel,
    dependencies=[Depends(enforce_rate_limit)],
)
async def fetch_url(
    url: str = Query(..., min_length=1, max_length=2048),
):
    """
    API7:2023 - Server Side Request Forgery (SSRF)
    --------------------------------------------------
    A rota aceita somente HTTPS para hosts exatos da allowlist configurada,
    rejeita redes privadas e fixa o IP público validado antes da conexão.
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
