"""Operações de autenticação da API."""

import os

from fastapi import HTTPException, Request

from models.LoginModel import LoginModel
from security import (
    DUMMY_PASSWORD_HASH,
    CurrentUser,
    authorize_object_access,
    create_access_token,
    verify_password,
)
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
            "token_type": "bearer",  # nosec B105
        }

    def get_user(self, user_id: int, current_user: CurrentUser):
        """
        API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
        --------------------------------------------------
        A autorização por objeto é aplicada antes do retorno: somente
        o próprio usuário ou um administrador pode acessar o registro
        indicado por `user_id`.

        API3:2023 - Excessive Data Exposure
        --------------------------------------------------
        O objeto inteiro do usuário é retornado sem filtrar campos
        sensíveis (senha, e-mail, dados internos), quando o cliente
        provavelmente só precisa de nome/ID.

        Ainda é necessário usar um DTO/schema de saída que exponha só os
        campos necessários.
        """
        authorize_object_access(current_user, user_id)

        user = users_db.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # O controle de taxa de requisições (API4:2023 - Unrestricted
        # Resource Consumption) continua pendente.
        return user

    def debug_info(self, request: Request):
        # O endpoint é mantido apenas para demonstrar a configuração de
        # ambiente. Segredos, headers e registros de usuários nunca devem
        # ser expostos, mesmo quando o modo de debug estiver habilitado.
        if DEBUG_MODE:
            return {"debug": True}
        raise HTTPException(status_code=404)
