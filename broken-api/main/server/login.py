from datetime import timedelta
from fastapi import APIRouter, HTTPException
from main.server.config import ACCESS_TOKEN_EXPIRE_MINUTES
from main.server.base import get_user_by_username
from main.server.token import LoginModel, Token
from main.server.auth import create_access_token

router = APIRouter()

@router.post("/login", response_model=Token)
def login(login_data: LoginModel):
    user = get_user_by_username(login_data.username)
    if not user or user["password"] != login_data.password:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}