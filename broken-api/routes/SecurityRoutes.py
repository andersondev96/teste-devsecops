"""Endpoint de metadados OWASP consumido automaticamente pelo painel."""

from fastapi import APIRouter

from controllers.SecurityStatusController import get_owasp_status
from models.SecurityStatusModel import OwaspStatusResponseModel


router = APIRouter(prefix="", tags=["Security"])


@router.get("/security/owasp", response_model=OwaspStatusResponseModel)
async def owasp_status():
    """Retorna o catálogo, status, evidências e métricas do backend."""

    return get_owasp_status()
