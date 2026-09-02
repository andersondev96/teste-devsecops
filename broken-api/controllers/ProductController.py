"""
ATENÇÃO — CÓDIGO INTENCIONALMENTE VULNERÁVEL
==============================================
Este arquivo foi modificado APENAS para fins didáticos, como base para um
trabalho sobre identificação e mitigação de vulnerabilidades do
OWASP API Security Top 10 (2023). NÃO utilize este código em produção
ou em qualquer ambiente exposto à internet.
"""

import logging
import sqlite3
import traceback
from math import isfinite
from pathlib import Path

from fastapi import HTTPException, status

from limits import MAX_PRODUCT_PRICE
from models.ProductModel import PublicProductModel
from security import CurrentUser, authorize_admin

DB_PATH = Path(__file__).resolve().parent.parent / "database.db"
logger = logging.getLogger(__name__)


class ProductController:
    @staticmethod
    def initialize_database():
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price REAL, cost REAL, internal_notes TEXT)"
        )
        cursor.execute("SELECT COUNT(*) FROM products")
        if cursor.fetchone()[0] == 0:
            # API3:2023 - Excessive Data Exposure (dado de apoio)
            # Campos internos permanecem armazenados separadamente dos
            # campos públicos retornados pelos serializers da API.
            cursor.executemany(
                "INSERT INTO products (name, price, cost, internal_notes) VALUES (?, ?, ?, ?)",
                [
                    ("Laptop", 1500.0, 900.0, "fornecedor: Acme Ltda, margem 40%"),
                    ("Mouse", 25.0, 8.0, "fornecedor: Acme Ltda, margem 68%"),
                    ("Keyboard", 75.0, 30.0, "fornecedor: Acme Ltda, margem 60%"),
                ],
            )
            conn.commit()
        conn.close()

    @staticmethod
    def get_products(limit: int, offset: int):
        """
        API4:2023 - Unrestricted Resource Consumption
        --------------------------------------------------
        A rota aplica paginação e recebe somente valores já validados
        pelos parâmetros limit/offset da camada HTTP. O limite máximo
        impede que uma única resposta carregue a tabela inteira.

        API3:2023 - Broken Object Property Level Authorization /
        Excessive Data Exposure
        --------------------------------------------------
        A consulta seleciona somente as colunas públicas e a resposta é
        validada por um DTO. `cost` e `internal_notes` permanecem internos.

        O tamanho da página e o deslocamento máximo são definidos pela
        rota para manter previsível o consumo de banco, memória e banda.
        """
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, price FROM products LIMIT ? OFFSET ?",
            (limit, offset),
        )
        products = cursor.fetchall()
        conn.close()
        return [
            PublicProductModel(
                id=product_id,
                name=name,
                price=price,
            ).model_dump()
            for product_id, name, price in products
        ]

    @staticmethod
    def search_products(name: str, limit: int, offset: int):
        """
        Hardening validado pelo SAST: consulta parametrizada
        --------------------------------------------------
        O nome recebido do cliente é enviado como um parâmetro do SQLite,
        e não concatenado na instrução SQL. Isso impede que o valor altere
        a estrutura da consulta ou seja interpretado como SQL.

        API8:2023 - Security Misconfiguration
        --------------------------------------------------
        O tratamento de erro detalhado continua mantido apenas como cenário
        didático de API8; respostas de produção devem registrar o detalhe
        no servidor e devolver uma mensagem genérica ao cliente.
        """
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        query = (
            "SELECT id, name, price FROM products "
            "WHERE name LIKE ? LIMIT ? OFFSET ?"
        )
        search_pattern = f"%{name}%"
        try:
            cursor.execute(query, (search_pattern, limit, offset))
            products = cursor.fetchall()
        except Exception as e:
            conn.close()
            # API8:2023 - Security Misconfiguration
            # Mensagens de erro detalhadas (stack trace, query executada)
            # devolvidas ao cliente ajudam um atacante a entender a
            # estrutura interna do banco e refinar o ataque.
            return {"error": str(e), "query": query, "trace": traceback.format_exc()}
        conn.close()
        return [
            PublicProductModel(
                id=product_id,
                name=product_name,
                price=price,
            ).model_dump()
            for product_id, product_name, price in products
        ]

    @staticmethod
    def get_product_for_checkout(product_id: int):
        """Retorna somente os dados de catálogo necessários ao checkout."""

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, name, price FROM products WHERE id = ?",
            (product_id,),
        )
        product = cursor.fetchone()
        conn.close()

        if product is None:
            return None

        return {
            "id": product[0],
            "name": product[1],
            "price": float(product[2]),
        }

    @staticmethod
    def delete_product(product_id: int, current_user: CurrentUser):
        """
        API5:2023 - Broken Function Level Authorization
        --------------------------------------------------
        A operação administrativa exige uma identidade autenticada com
        função de administrador. A verificação é feita na rota e repetida
        no controlador para evitar que chamadas internas contornem a política.
        """
        authorize_admin(current_user)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()

        if deleted == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")

        logger.info(
            "product_deleted admin_user_id=%s product_id=%s",
            current_user.id,
            product_id,
        )
        return {"status": "deleted", "id": product_id}

    @staticmethod
    def update_price(product_id: int, new_price: float, current_user: CurrentUser):
        """
        API5:2023 - Broken Function Level Authorization
        --------------------------------------------------
        Alterações de catálogo exigem função administrativa, validam uma
        faixa de preço positiva e registram a operação sem dados sensíveis.
        """
        authorize_admin(current_user)
        if not isfinite(new_price) or not 0 < new_price <= MAX_PRODUCT_PRICE:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="new_price must be greater than zero and within the allowed limit",
            )

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE products SET price = ? WHERE id = ?", (new_price, product_id))
        updated = cursor.rowcount
        conn.commit()
        conn.close()

        if updated == 0:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Product not found")

        logger.info(
            "product_price_updated admin_user_id=%s product_id=%s",
            current_user.id,
            product_id,
        )
        return {"status": "updated", "id": product_id, "new_price": new_price}
