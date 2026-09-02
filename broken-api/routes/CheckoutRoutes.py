"""
ATENÇÃO — ROTAS INTENCIONALMENTE VULNERÁVEIS
==============================================
Rotas de Checkout. Uso didático (trabalho sobre OWASP API
Security Top 10). NÃO utilize em produção.
"""

from fastapi import APIRouter, Depends

from controllers.CheckoutController import CheckoutController
from limits import enforce_rate_limit
from models.CheckoutModel import CheckoutRequestModel, CheckoutResponseModel
from security import CurrentUser, get_current_user

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


@router.get("/checkout/debug")
async def checkout_debug():
    """
    API9:2023 - Improper Inventory Management
    --------------------------------------------------
    Vaza todos os pedidos de todos os clientes, sem autenticação.
    """
    return await checkout_controller.debug_orders()
