"""
ATENÇÃO — ROTAS INTENCIONALMENTE VULNERÁVEIS
==============================================
Rotas de Autenticação. Uso didático (trabalho sobre OWASP API
Security Top 10). NÃO utilize em produção.
"""

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
    Token gerado sem validar senha, sem assinatura, sem expiração
    (apenas Base64 do username). Ver AuthController.login().
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
    API9:2023 - Improper Inventory Management
    API8:2023 - Security Misconfiguration
    --------------------------------------------------
    Endpoint de debug esquecido, sem autenticação, que vaza headers,
    segredos do sistema e a base de usuários inteira.
    """
    return auth_controller.debug_info(request)