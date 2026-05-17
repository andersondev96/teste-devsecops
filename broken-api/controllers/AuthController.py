import os
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Header, HTTPException, status

from models.LoginModel import LoginModel
from users_db import users_db

SECRET_KEY = os.getenv("SECRET_KEY", "b3_ch4r_r4nd0m_s7r1ng_s4f3_f0r_7cc")
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 30


class AuthController:
    @staticmethod
    def login(login_data: LoginModel):
        user = next((u for u in users_db.values() if u["username"] == login_data.username), None)
        if not user or user["password"] != login_data.password:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciais invalidas",
            )

        expires_at = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
        access_token = jwt.encode(
            {"sub": user["username"], "exp": expires_at},
            SECRET_KEY,
            algorithm=ALGORITHM,
        )
        return {"access_token": access_token, "token_type": "bearer"}

    @staticmethod
    def get_current_user(authorization: Optional[str] = Header(None)):
        if not authorization:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciais ausentes",
            )

        prefix = "Bearer "
        token = authorization[len(prefix):] if authorization.startswith(prefix) else authorization

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if not username:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token invalido",
                )
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expirado")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalido")

        user = next((u for u in users_db.values() if u["username"] == username), None)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario nao encontrado",
            )

        return user
