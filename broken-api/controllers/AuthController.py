"""Operações de autenticação da API."""

from fastapi import HTTPException

from models.LoginModel import LoginModel
from models.UserModel import PublicUserModel
from security import (
    DUMMY_PASSWORD_HASH,
    CurrentUser,
    authorize_object_access,
    create_access_token,
    verify_password,
)
from users_db import users_db


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
        A resposta usa um DTO público com somente ID e nome de usuário.
        Hash de senha, e-mail, papel administrativo e outros campos
        internos nunca são serializados para o cliente.

        A autorização por objeto da API1 continua sendo aplicada antes
        da serialização.
        """
        authorize_object_access(current_user, user_id)

        user = users_db.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # A rota aplica o rate limiting da API4 antes de chegar ao
        # controlador; a resposta continua limitada ao DTO público.
        return PublicUserModel(
            id=user["id"],
            username=user["username"],
        ).model_dump()
