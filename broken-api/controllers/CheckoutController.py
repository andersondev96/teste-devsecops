"""
ATENÇÃO — CÓDIGO INTENCIONALMENTE VULNERÁVEL
==============================================
Este arquivo foi modificado APENAS para fins didáticos, como base para um
trabalho sobre identificação e mitigação de vulnerabilidades do
OWASP API Security Top 10 (2023). NÃO utilize este código em produção
ou em qualquer ambiente exposto à internet.
"""

import logging

from fastapi import HTTPException, status

from controllers.ProductController import ProductController
from limits import MAX_CHECKOUT_TOTAL, enforce_business_flow_limit
from models.CheckoutModel import (
    CheckoutRequestModel,
    CheckoutResponseModel,
    PublicOrderModel,
)
from security import CurrentUser, authorize_object_access
from users_db import checkout_db  # simulação de "banco" em memória

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------
# API8:2023 - Security Misconfiguration
# Flag de debug ligada por padrão, sem controle de ambiente
# (deveria vir de variável de ambiente, nunca hardcoded como True).
# --------------------------------------------------------------------
DEBUG = True


class CheckoutController:
    def __init__(self):
        self.checkout_db = checkout_db

    async def complete_checkout(
        self,
        checkout_data: CheckoutRequestModel,
        current_user: CurrentUser,
    ) -> CheckoutResponseModel:
        """
        API6:2023 - Unrestricted Access to Sensitive Business Flows
        --------------------------------------------------
        O fluxo exige autenticação, limita tentativas pela identidade,
        valida produto, quantidade e método de pagamento no servidor,
        calcula o total a partir do catálogo e impede reutilização
        inconsistente do mesmo identificador de pedido. CAPTCHA e
        detecção avançada de automação permanecem controles complementares.

        API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
        --------------------------------------------------
        O `order_id` é validado contra o usuário autenticado antes do
        processamento. Pedidos existentes de outro usuário são
        rejeitados, e novos pedidos recebem o ID do usuário autenticado.

        API3:2023 - Broken Object Property Level Authorization
        (Mass Assignment)
        --------------------------------------------------
        O schema de entrada usa uma allowlist explícita (`order_id` e
        `payment_method`) e rejeita propriedades extras. Preço, desconto,
        status de pagamento, proprietário e demais campos internos não
        podem ser enviados nem alterados pelo cliente.

        API4:2023 - Unrestricted Resource Consumption
        --------------------------------------------------
        O middleware rejeita corpos maiores que 64 KiB, inclusive quando
        chegam em múltiplos chunks, e a rota aplica rate limiting. O
        timeout de infraestrutura deve ser configurado no servidor/gateway.

        Mitigação (para o trabalho):
          - Exigir autenticação (JWT) e checar que order.user_id ==
            usuário autenticado antes de qualquer operação (API1).
          - Usar um schema de entrada (Pydantic) que só aceite campos
            permitidos — nunca usar o dict inteiro do request.
          - Aplicar limite por identidade e limite de payload em fluxos de
            negócio sensíveis; CAPTCHA e detecção de automação são controles
            complementares da API6.
          - Nunca confiar em preço/desconto/status vindos do cliente;
            recalcular o total no servidor a partir do catálogo.
        """
        enforce_business_flow_limit(current_user.id)
        order_id = checkout_data.order_id

        order = self.checkout_db.get(order_id)

        if order:
            try:
                owner_id = int(order.get("user_id"))
            except (AttributeError, TypeError, ValueError):
                # Registros sem proprietário confiável não podem ser
                # acessados por uma requisição autenticada comum.
                raise HTTPException(status_code=403, detail="Forbidden")
            authorize_object_access(current_user, owner_id)

            if order.get("status") == "completed":
                same_request = all(
                    order.get(field) == value
                    for field, value in {
                        "product_id": checkout_data.product_id,
                        "quantity": checkout_data.quantity,
                        "payment_method": checkout_data.payment_method,
                    }.items()
                )
                if same_request:
                    return self._build_response(order_id, order)
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Order already completed with different data",
                )

            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Order cannot be reused",
            )
        else:
            owner_id = current_user.id

        product = ProductController.get_product_for_checkout(checkout_data.product_id)
        if product is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")

        total = round(product["price"] * checkout_data.quantity, 2)
        if total > MAX_CHECKOUT_TOTAL:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Order total exceeds the allowed limit",
            )

        # O pedido contém somente valores de negócio calculados/validados no
        # servidor. Preço, desconto, status e proprietário não vêm do cliente.
        order_data = {
            "user_id": owner_id,
            "product_id": product["id"],
            "quantity": checkout_data.quantity,
            "payment_method": checkout_data.payment_method,
            "unit_price": product["price"],
            "total": total,
            "status": "completed",
        }
        self.checkout_db[order_id] = order_data
        logger.info(
            "checkout_completed user_id=%s order_id=%s product_id=%s quantity=%s total=%s",
            current_user.id,
            order_id,
            product["id"],
            checkout_data.quantity,
            total,
        )
        return self._build_response(order_id, order_data)

    @staticmethod
    def _build_response(order_id: str, order_data: dict) -> CheckoutResponseModel:
        """Serializa somente o estado público e validado do pedido."""

        public_order = PublicOrderModel(
            order_id=order_id,
            product_id=order_data["product_id"],
            quantity=order_data["quantity"],
            payment_method=order_data["payment_method"],
            total=order_data["total"],
            status=order_data["status"],
        )
        return CheckoutResponseModel(status="success", order=public_order)

    async def debug_orders(self):
        if DEBUG:
            # API9 continua expondo o inventário completo, mas a API3 não
            # deve vazar propriedades internas de cada pedido.
            return {
                "all_orders": {
                    order_id: PublicOrderModel(
                        order_id=order_id,
                        product_id=order["product_id"],
                        quantity=order["quantity"],
                        payment_method=order.get("payment_method"),
                        total=order["total"],
                        status=order["status"],
                    ).model_dump()
                    for order_id, order in self.checkout_db.items()
                }
            }
        return {"detail": "Not found"}
