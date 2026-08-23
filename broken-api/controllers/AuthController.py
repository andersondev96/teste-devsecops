"""
ATENÇÃO — CÓDIGO INTENCIONALMENTE VULNERÁVEL
==============================================
Este arquivo foi modificado APENAS para fins didáticos, como base para um
trabalho sobre identificação e mitigação de vulnerabilidades do
OWASP API Security Top 10 (2023). NÃO utilize este código em produção
ou em qualquer ambiente exposto à internet.

Cada bloco abaixo contém um comentário indicando:
  - O item do OWASP API Top 10 explorado
  - Por que aquele trecho é vulnerável
  - (sugestão) o que precisaria ser feito para mitigar
"""

from fastapi import HTTPException, Request
from typing import Any, Dict
import base64
import hashlib
from models.LoginModel import LoginModel
from users_db import users_db

# --------------------------------------------------------------------
# API8:2023 - Security Misconfiguration
# Segredos hardcoded diretamente no código-fonte (deveriam vir de
# variáveis de ambiente / secret manager). Se este repositório vazar
# (ex: git público), as credenciais reais vazam junto.
# --------------------------------------------------------------------
SECRET_KEY = "b3_ch4r_r4nd0m_s7r1ng_s4f3_f0r_7cc"
DB_PASSWORD = "secret_admin_password"

# --------------------------------------------------------------------
# API9:2023 - Improper Inventory Management (simulação)
# Endpoint de debug esquecido, que expõe informações internas sensíveis.
# Nenhuma autenticação, nenhuma restrição de ambiente (dev vs prod).
# --------------------------------------------------------------------
DEBUG_MODE = True


class AuthController:

    def login(self, login_data: LoginModel):
        """
        API2:2023 - Broken Authentication
        --------------------------------------------------
        O "token" é apenas o username codificado em Base64 — não há
        verificação de senha, não há assinatura criptográfica (ex: JWT
        com HMAC/RSA), não há expiração. Qualquer pessoa pode forjar um
        token válido para QUALQUER usuário só codificando o nome em
        Base64 (base64 não é criptografia, é apenas codificação
        reversível). Isso permite personificação total de qualquer conta.

        API3:2023 - Broken Object Property Level Authorization /
        Excessive Data Exposure
        --------------------------------------------------
        A resposta devolve dados internos que o cliente não deveria ver
        (senha em texto legível, chave secreta), facilitando ataques
        subsequentes.

        Mitigação (para o trabalho): usar hashing de senha (bcrypt/argon2),
        gerar JWT assinado com expiração e claims mínimas, nunca devolver
        segredos internos na resposta.
        """
        user = None
        for u in users_db.values():
            if u.get("username") == login_data.username:
                user = u
                break

        # Nenhuma validação real de senha: mesmo se `password` existir
        # no modelo, ela é ignorada — qualquer senha é aceita.
        # (API2:2023 - Broken Authentication)
        fake_token = base64.b64encode(login_data.username.encode()).decode()

        # Tipagem explícita como Dict[str, Any] — sem isso, o Pyright/Pylance
        # infere o dicionário como dict[str, str] (baseado nos dois valores
        # iniciais) e reclama quando tentamos guardar um dict (user) ou
        # outros tipos nas chaves seguintes.
        response: Dict[str, Any] = {
            "access_token": fake_token,
            "token_type": "bearer",
        }

        # API3:2023 - Excessive Data Exposure: devolvendo dados sensíveis
        # que não deveriam sair da API (senha, chave secreta do sistema).
        if user:
            response["user_debug"] = user  # pode conter senha em texto puro
            response["server_secret"] = SECRET_KEY

        return response

    def get_user(self, user_id: int):
        """
        API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
        --------------------------------------------------
        Não há verificação se o solicitante tem permissão para acessar
        o registro `user_id`. Qualquer usuário autenticado (ou até não
        autenticado, pois este método não checa token nenhum) pode
        buscar dados de QUALQUER outro usuário apenas trocando o ID
        na URL (ex: /users/1, /users/2, /users/3...), permitindo
        enumeração completa da base.

        API3:2023 - Excessive Data Exposure
        --------------------------------------------------
        O objeto inteiro do usuário é retornado sem filtrar campos
        sensíveis (senha, e-mail, dados internos), quando o cliente
        provavelmente só precisa de nome/ID.

        Mitigação (para o trabalho): validar que o `user_id` solicitado
        corresponde ao usuário autenticado (ou que ele tem role de admin),
        usar um DTO/schema de saída que exponha só os campos necessários.
        """
        user = users_db.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Nenhuma checagem de autorização (BOLA) e nenhum controle de
        # taxa de requisições (API4:2023 - Unrestricted Resource
        # Consumption): este endpoint pode ser chamado em loop para
        # enumerar todos os IDs sem nenhum rate limiting.
        return user

    def debug_info(self, request: Request):
        if DEBUG_MODE:
            return {
                "headers": dict(request.headers),
                "db_password": DB_PASSWORD,
                "secret_key": SECRET_KEY,
                "all_users": users_db,  # vaza a base inteira de usuários
            }
        raise HTTPException(status_code=404)