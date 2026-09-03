"""
ATENÇÃO — ROTAS INTENCIONALMENTE VULNERÁVEIS
==============================================
Rotas de Checkout. Uso didático (trabalho sobre OWASP API
Security Top 10). NÃO utilize em produção.
"""

from typing import List

from fastapi import APIRouter, Depends, Query

from controllers.CheckoutController import CheckoutController
from limits import DEFAULT_PAGE_SIZE, MAX_OFFSET, MAX_PAGE_SIZE, enforce_rate_limit
from models.CheckoutModel import AdminOrderModel, CheckoutRequestModel, CheckoutResponseModel
from security import CurrentUser, get_current_user, require_admin

router = APIRouter(prefix="", tags=["Checkout"])

checkout_controller = CheckoutController()


@router.post(
    "/checkout",
    response_model=CheckoutResponseModel,
    dependencies=[Depends(enforce_rate_limit)],
)
async def complete_checkout(
    checkout_data: CheckoutRequestModel,
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    API6:2023 - Unrestricted Access to Sensitive Business Flows
    --------------------------------------------------
    Fluxo de negócio sensível protegido por autenticação, limite por
    identidade, allowlist de campos, validação de catálogo, cálculo de
    total no servidor e idempotência do pedido. CAPTCHA e detecção de
    automação permanecem controles complementares.

    API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
    --------------------------------------------------
    `order_id` do corpo é validado contra o usuário autenticado antes
    de qualquer alteração no pedido.

    API3:2023 - Broken Object Property Level Authorization
    (Mass Assignment)
    --------------------------------------------------
    O schema de entrada aceita somente propriedades permitidas e a
    resposta usa um DTO sem campos internos. Ver
    CheckoutController.complete_checkout().
    """
    return await checkout_controller.complete_checkout(checkout_data, current_user)


@router.get(
    "/admin/inventory/orders",
    response_model=List[AdminOrderModel],
    dependencies=[Depends(enforce_rate_limit)],
)
async def list_inventory_orders(
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(0, ge=0, le=MAX_OFFSET),
    current_user: CurrentUser = Depends(require_admin),
):
    """
    API9:2023 - Improper Inventory Management
    --------------------------------------------------
    Inventário operacional documentado, autenticado, autorizado por
    função e paginado. O endpoint legado de debug foi removido.
    """
    return checkout_controller.list_inventory(limit, offset, current_user)
