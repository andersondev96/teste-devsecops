"""
ATENÇÃO — CÓDIGO INTENCIONALMENTE VULNERÁVEL
==============================================
Este arquivo foi modificado APENAS para fins didáticos, como base para um
trabalho sobre identificação e mitigação de vulnerabilidades do
OWASP API Security Top 10 (2023). NÃO utilize este código em produção
ou em qualquer ambiente exposto à internet.
"""

import sqlite3
import traceback
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "database.db"


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
            # API3:2023 - Excessive Data Exposure (preparação)
            # Campos internos (custo real, notas internas de negociação
            # com fornecedor) sendo guardados na MESMA tabela que será
            # devolvida sem filtro nenhum ao cliente da API.
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
    def get_products():
        """
        API4:2023 - Unrestricted Resource Consumption
        --------------------------------------------------
        Nenhuma paginação, LIMIT ou controle de tamanho de resposta.
        Com uma tabela grande, esta rota pode ser usada para causar
        esgotamento de memória/CPU/banda (ex: chamando repetidamente
        uma tabela com milhões de linhas).

        API3:2023 - Broken Object Property Level Authorization /
        Excessive Data Exposure
        --------------------------------------------------
        `SELECT *` devolve TODAS as colunas, incluindo `cost` e
        `internal_notes`, que são dados internos de negócio e nunca
        deveriam ser expostos por uma API pública de catálogo.

        Mitigação: usar paginação (LIMIT/OFFSET ou cursor), selecionar
        explicitamente só as colunas públicas (id, name, price), e
        aplicar um schema de saída (DTO) que filtre o restante.
        """
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products")
        products = cursor.fetchall()
        conn.close()
        return products

    @staticmethod
    def search_products(name: str):
        """
        API8:2023 - Security Misconfiguration / Injection
        (SQL Injection — historicamente API8 no Top 10, mas tratado
        como falha de configuração/validação de entrada no OWASP API
        Security Top 10 2023, já que "Injection" deixou de ser
        categoria própria e virou consequência de más práticas gerais)
        --------------------------------------------------
        A busca concatena a entrada do usuário DIRETO na query SQL,
        sem parâmetros preparados (`?`). Isso permite SQL Injection
        clássico, por exemplo:

            name = "' OR '1'='1"          -> vaza a tabela inteira
            name = "' UNION SELECT sqlite_version(),1,1,1 --"
                                            -> extrai metadados do banco

        Mitigação: SEMPRE usar queries parametrizadas
        (cursor.execute("... WHERE name LIKE ?", (f"%{name}%",))),
        nunca montar SQL via f-string/concatenação com dado do usuário.
        """
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        query = f"SELECT * FROM products WHERE name LIKE '%{name}%'"  # VULNERÁVEL: SQL Injection
        try:
            cursor.execute(query)
            products = cursor.fetchall()
        except Exception as e:
            conn.close()
            # API8:2023 - Security Misconfiguration
            # Mensagens de erro detalhadas (stack trace, query executada)
            # devolvidas ao cliente ajudam um atacante a entender a
            # estrutura interna do banco e refinar o ataque.
            return {"error": str(e), "query": query, "trace": traceback.format_exc()}
        conn.close()
        return products

    @staticmethod
    def delete_product(product_id: int):
        """
        API5:2023 - Broken Function Level Authorization
        --------------------------------------------------
        Operação administrativa (exclusão de produto) exposta sem
        NENHUMA verificação de papel/permissão (role admin vs cliente
        comum). Qualquer usuário — autenticado ou não — pode apagar
        qualquer produto do catálogo apenas conhecendo o ID.

        Mitigação: verificar explicitamente se o usuário autenticado
        possui role "admin" (ou permissão equivalente) antes de
        executar operações destrutivas; nunca confiar apenas na
        existência de um token válido.
        """
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM products WHERE id = ?", (product_id,))
        conn.commit()
        conn.close()
        return {"status": "deleted", "id": product_id}

    @staticmethod
    def update_price(product_id: int, new_price: float):
        """
        API5:2023 - Broken Function Level Authorization
        API6:2023 - Unrestricted Access to Sensitive Business Flows
        --------------------------------------------------
        Qualquer chamador pode alterar o preço de qualquer produto,
        sem autenticação, sem log de auditoria, e sem limite de valor
        (aceita preço negativo ou zero, permitindo abuso financeiro
        direto no fluxo de vendas).

        Mitigação: exigir role admin, validar faixa de valores
        aceitáveis, e registrar (log/auditoria) quem alterou o quê.
        """
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE products SET price = ? WHERE id = ?", (new_price, product_id))
        conn.commit()
        conn.close()
        return {"status": "updated", "id": product_id, "new_price": new_price}