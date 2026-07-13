"""
ATENÇÃO — CÓDIGO INTENCIONALMENTE VULNERÁVEL
==============================================
Este arquivo foi modificado APENAS para fins didáticos, como base para um
trabalho sobre identificação e mitigação de vulnerabilidades do
OWASP API Security Top 10 (2023). NÃO utilize este código em produção
ou em qualquer ambiente exposto à internet.
"""

from fastapi import Request
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

    async def complete_checkout(self, request: Request):
        """
        API6:2023 - Unrestricted Access to Sensitive Business Flows
        --------------------------------------------------
        O fluxo de checkout (uma ação de negócio sensível, que
        movimenta dinheiro/estoque) não possui:
          - autenticação do usuário
          - CAPTCHA / rate limiting
          - verificação de que o pedido pertence ao usuário logado
        Isso permite que um bot finalize checkouts em massa, abuse de
        cupons de desconto, ou finalize pedidos de outras pessoas.

        API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
        --------------------------------------------------
        Qualquer `order_id` enviado no corpo é aceito e processado sem
        checar se ele pertence ao usuário que está fazendo a
        requisição. Um atacante pode iterar `order_id` para finalizar
        (ou consultar) pedidos de terceiros.

        API3:2023 - Broken Object Property Level Authorization
        (Mass Assignment)
        --------------------------------------------------
        Todo o corpo (`data`) é confiado e aplicado diretamente sobre
        o registro do pedido, incluindo campos que o cliente NUNCA
        deveria poder alterar (preço, desconto, status de pagamento,
        flag de admin etc.). Isso é conhecido como "Mass Assignment":
        o atacante manda { "price": 0.01, "is_paid": true } e o
        servidor aceita cegamente.

        API4:2023 - Unrestricted Resource Consumption
        --------------------------------------------------
        Nenhum limite de tamanho de payload, nenhum rate limiting,
        nenhum timeout — a rota pode ser chamada em loop infinito ou
        com corpos gigantes, consumindo CPU/memória do servidor.

        Mitigação (para o trabalho):
          - Exigir autenticação (JWT) e checar que order.user_id ==
            usuário autenticado antes de qualquer operação (BOLA).
          - Usar um schema de entrada (Pydantic) que só aceite campos
            permitidos (ex: order_id, payment_method) — nunca usar o
            dict inteiro do request.
          - Aplicar rate limiting (ex: slowapi) e CAPTCHA em fluxos de
            negócio sensíveis.
          - Nunca confiar em preço/desconto vindos do cliente; recalcular
            sempre no servidor a partir da fonte confiável (catálogo/BD).
        """
        data = await request.json()
        order_id = data.get("order_id")

        order = self.checkout_db.get(order_id)

        # Mass Assignment: aplica QUALQUER campo enviado pelo cliente
        # diretamente no registro do pedido, sem validar nomes de
        # campos nem tipos. (API3:2023)
        if order:
            order.update(data)
        else:
            # Se o pedido não existe, cria um novo do zero com os dados
            # do cliente — incluindo campos sensíveis como "price",
            # "discount", "is_paid" que deveriam ser calculados no
            # servidor. (API3:2023 + API6:2023)
            self.checkout_db[order_id] = data

        # API3:2023 - Excessive Data Exposure
        # Devolve o registro inteiro do pedido, incluindo qualquer
        # campo interno (ex: custo real, margem, dados de outro
        # cliente reaproveitados por engano) em vez de um DTO de saída.
        return {
            "status": "success",
            "order": self.checkout_db.get(order_id),
        }

    async def debug_orders(self):
        """
        API9:2023 - Improper Inventory Management
        --------------------------------------------------
        Endpoint de depuração que expõe TODOS os pedidos de TODOS os
        usuários, sem nenhuma autenticação, provavelmente esquecido
        ao subir para produção. Rotas assim raramente aparecem na
        documentação oficial da API e são achadas por varredura,
        virando uma porta de entrada fácil.

        Mitigação: remover endpoints de debug antes do deploy, ou
        protegê-los com autenticação de admin + feature flag de
        ambiente (nunca habilitado em produção).
        """
        if DEBUG:
            return {"all_orders": self.checkout_db}
        return {"detail": "Not found"}