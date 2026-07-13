"""
ATENÇÃO — ROTAS INTENCIONALMENTE VULNERÁVEIS
==============================================
Rotas de Usuários. Uso didático (trabalho sobre OWASP API
Security Top 10). NÃO utilize em produção.
"""

from fastapi import APIRouter

from controllers.UserController import UserController

router = APIRouter(prefix="", tags=["Usuários"])

user_controller = UserController()


@router.get("/profile/{user_id}")
async def get_user_profile(user_id: int, current_user_id: int):
    """
    API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
    --------------------------------------------------
    `current_user_id` chega como QUERY PARAM informado pelo próprio
    cliente (não extraído de um token validado) e nunca é comparado
    com `user_id` -> qualquer um lê o perfil de qualquer um só
    trocando os números na URL, ex:
        GET /profile/2?current_user_id=1

    API3:2023 - Excessive Data Exposure
    --------------------------------------------------
    Devolve o objeto de usuário inteiro (senha incluída).
    """
    return user_controller.get_user_profile(user_id, current_user_id)


@router.put("/profile/{user_id}")
async def update_user_profile(user_id: int, current_user_id: int, data: dict):
    """
    API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
    --------------------------------------------------
    Mesma falha da rota GET: `current_user_id` não é validado contra
    `user_id`, permitindo editar o perfil de qualquer usuário.

    API3:2023 - Broken Object Property Level Authorization
    (Mass Assignment)
    --------------------------------------------------
    `data` (corpo cru da requisição) é aplicado sem allowlist, ex:
        PUT /profile/1?current_user_id=1
        { "is_admin": true }
    promove o próprio usuário a administrador.
    """
    return user_controller.update_user_profile(user_id, current_user_id, data)


@router.delete("/profile/{user_id}")
async def delete_user(user_id: int, current_user_id: int):
    """
    API5:2023 - Broken Function Level Authorization
    --------------------------------------------------
    Exclusão de conta sem checar se `current_user_id` é o próprio
    dono ou um admin -> qualquer chamador apaga qualquer conta.
    """
    return user_controller.delete_user(user_id, current_user_id)


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