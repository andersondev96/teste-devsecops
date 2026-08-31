"""
ATENÇÃO — ROTAS INTENCIONALMENTE VULNERÁVEIS
==============================================
Rotas de Usuários. Uso didático (trabalho sobre OWASP API
Security Top 10). NÃO utilize em produção.
"""

from fastapi import APIRouter, Depends

from controllers.UserController import UserController
from security import CurrentUser, get_current_user

router = APIRouter(prefix="", tags=["Usuários"])

user_controller = UserController()


@router.get("/profile/{user_id}")
async def get_user_profile(
    user_id: int,
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
    --------------------------------------------------
    A identidade é extraída de um JWT validado no servidor. O acesso
    é permitido somente ao próprio usuário ou a um administrador;
    `current_user_id` enviado como query parameter não altera essa
    identidade.

    API3:2023 - Excessive Data Exposure
    --------------------------------------------------
    Devolve o objeto de usuário inteiro (senha incluída).
    """
    return user_controller.get_user_profile(user_id, current_user)


@router.put("/profile/{user_id}")
async def update_user_profile(
    user_id: int,
    data: dict,
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
    --------------------------------------------------
    A identidade é extraída de um JWT validado no servidor e o acesso
    ao objeto é permitido somente ao dono ou a um administrador.

    API3:2023 - Broken Object Property Level Authorization
    (Mass Assignment)
    --------------------------------------------------
    `data` (corpo cru da requisição) é aplicado sem allowlist, ex:
        PUT /profile/1
        { "is_admin": true }
    promove o próprio usuário a administrador.
    """
    return user_controller.update_user_profile(user_id, current_user, data)


@router.delete("/profile/{user_id}")
async def delete_user(
    user_id: int,
    current_user: CurrentUser = Depends(get_current_user),
):
    """
    API5:2023 - Broken Function Level Authorization
    --------------------------------------------------
    A identidade é extraída de um JWT e o acesso ao objeto é limitado
    ao próprio dono ou a um administrador.
    """
    return user_controller.delete_user(user_id, current_user)


@router.get("/users")
async def list_all_users():
    """
    API3:2023 - Excessive Data Exposure
    API9:2023 - Improper Inventory Management
    --------------------------------------------------
    Endpoint "utilitário" sem autenticação nem paginação que vaza
    a base de usuários inteira (incluindo senhas em texto puro).
    """
    return user_controller.list_all_users()
