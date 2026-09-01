"""
ATENÇÃO — CÓDIGO INTENCIONALMENTE VULNERÁVEL
==============================================
Este arquivo foi modificado APENAS para fins didáticos, como base para um
trabalho sobre identificação e mitigação de vulnerabilidades do
OWASP API Security Top 10 (2023). NÃO utilize este código em produção
ou em qualquer ambiente exposto à internet.
"""

from fastapi import HTTPException
from models.CheckoutModel import (
    CheckoutRequestModel,
    CheckoutResponseModel,
    PublicOrderModel,
)
from security import CurrentUser, authorize_object_access
from users_db import checkout_db  # simulação de "banco" em memória

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
        O fluxo de checkout (uma ação de negócio sensível, que
        movimenta dinheiro/estoque) possui autenticação, rate limiting
        por origem/rota e limite global de tamanho de corpo. CAPTCHA e
        detecção avançada de automação permanecem controles da API6.

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
          - Aplicar rate limiting e limite de payload em fluxos de negócio
            sensíveis; CAPTCHA e detecção de automação são controles da API6.
          - Nunca confiar em preço/desconto vindos do cliente; recalcular
            sempre no servidor a partir da fonte confiável (catálogo/BD).
        """
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
        else:
            owner_id = current_user.id

        # Persiste somente a propriedade permitida pelo schema. O
        # proprietário é sempre um campo interno definido pelo servidor.
        if checkout_data.payment_method is not None:
            safe_data = {"payment_method": checkout_data.payment_method}
        else:
            safe_data = {}

        if order:
            order.update(safe_data)
        else:
            # O pedido contém apenas o identificador interno do proprietário
            # e as propriedades permitidas para o fluxo.
            self.checkout_db[order_id] = {"user_id": owner_id, **safe_data}

        # API3:2023 - Excessive Data Exposure
        # O DTO omite o proprietário e todos os campos internos do pedido.
        order_data = self.checkout_db.get(order_id, {})
        public_order = PublicOrderModel(
            order_id=order_id,
            payment_method=order_data.get("payment_method"),
        )
        return CheckoutResponseModel(
            status="success",
            order=public_order,
        )

    async def debug_orders(self):
        if DEBUG:
            # API9 continua expondo o inventário completo, mas a API3 não
            # deve vazar propriedades internas de cada pedido.
            return {
                "all_orders": {
                    order_id: PublicOrderModel(
                        order_id=order_id,
                        payment_method=order.get("payment_method"),
                    ).model_dump()
                    for order_id, order in self.checkout_db.items()
                }
            }
        return {"detail": "Not found"}
