"""Operações de autenticação da API."""

import os

from fastapi import HTTPException, Request

from models.LoginModel import LoginModel
from security import DUMMY_PASSWORD_HASH, create_access_token, verify_password
from users_db import users_db

DEBUG_MODE = os.getenv("DEBUG_MODE", "false").lower() == "true"


class AuthController:

    def login(self, login_data: LoginModel):
        user = next(
            (candidate for candidate in users_db.values()
             if candidate.get("username") == login_data.username),
            None,
        )

        password_hash = user.get("password_hash") if user else None
        password_is_valid = verify_password(
            login_data.password,
            password_hash or DUMMY_PASSWORD_HASH,
        )

        if not user or not password_is_valid:
            raise HTTPException(
                status_code=401,
                detail="Invalid username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return {
            "access_token": create_access_token(user["id"]),
            "token_type": "bearer",
        }

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
        # O endpoint é mantido apenas para demonstrar a configuração de
        # ambiente. Segredos, headers e registros de usuários nunca devem
        # ser expostos, mesmo quando o modo de debug estiver habilitado.
        if DEBUG_MODE:
            return {"debug": True}
        raise HTTPException(status_code=404)
