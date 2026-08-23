"""
ATENÇÃO — ROTAS INTENCIONALMENTE VULNERÁVEIS
==============================================
Rotas de Checkout. Uso didático (trabalho sobre OWASP API
Security Top 10). NÃO utilize em produção.
"""

from fastapi import APIRouter, Request

from controllers.CheckoutController import CheckoutController

router = APIRouter(prefix="", tags=["Checkout"])

checkout_controller = CheckoutController()


@router.post("/checkout")
async def complete_checkout(request: Request):
    """
    API6:2023 - Unrestricted Access to Sensitive Business Flows
    --------------------------------------------------
    Fluxo de negócio sensível (finalizar compra) sem autenticação,
    CAPTCHA ou rate limiting -> permite abuso automatizado (bots).

    API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
    --------------------------------------------------
    `order_id` do corpo não é validado contra o usuário da requisição.

    API3:2023 - Broken Object Property Level Authorization
    (Mass Assignment)
    --------------------------------------------------
    O corpo inteiro da requisição é aplicado sobre o pedido, incluindo
    campos que o cliente nunca deveria poder alterar (preço, status
    de pagamento etc.). Ver CheckoutController.complete_checkout().
    """
    return await checkout_controller.complete_checkout(request)


@router.get("/checkout/debug")
async def checkout_debug():
    """
    API9:2023 - Improper Inventory Management
    --------------------------------------------------
    Vaza todos os pedidos de todos os clientes, sem autenticação.
    """
    return await checkout_controller.debug_orders()