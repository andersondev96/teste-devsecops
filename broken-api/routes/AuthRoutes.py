"""Rotas de autenticação da API."""

from fastapi import APIRouter, Request

from controllers.AuthController import AuthController
from models.LoginModel import LoginModel

router = APIRouter(prefix="", tags=["Autenticação"])

auth_controller = AuthController()


@router.post("/login")
async def login(login_data: LoginModel):
    """
    API2:2023 - Broken Authentication
    --------------------------------------------------
    A senha é validada contra hash scrypt e o token é um JWT assinado,
    com expiração e claims mínimas. O endpoint não devolve dados internos.
    """
    return auth_controller.login(login_data)


@router.get("/users/{user_id}")
async def get_user(user_id: int):
    """
    API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
    --------------------------------------------------
    Rota pública, sem autenticação e sem checar se o solicitante pode
    ver este `user_id` -> permite enumeração de toda a base
    (/users/1, /users/2, /users/3 ...).

    API4:2023 - Unrestricted Resource Consumption
    --------------------------------------------------
    Nenhum rate limiting: a rota pode ser varrida em loop.
    """
    return auth_controller.get_user(user_id)


@router.get("/auth/debug")
async def auth_debug(request: Request):
    """
    Endpoint legado de debug, desabilitado por padrão.
    --------------------------------------------------
    Quando habilitado explicitamente, não devolve headers, segredos ou
    registros de usuários.
    """
    return auth_controller.debug_info(request)
