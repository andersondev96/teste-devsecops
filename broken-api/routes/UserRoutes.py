"""
ATENÇÃO — ROTAS INTENCIONALMENTE VULNERÁVEIS
==============================================
Rotas de Usuários. Uso didático (trabalho sobre OWASP API
Security Top 10). NÃO utilize em produção.
"""

from typing import List

from fastapi import APIRouter, Depends, Query

from controllers.UserController import UserController
from limits import DEFAULT_PAGE_SIZE, MAX_OFFSET, MAX_PAGE_SIZE, enforce_rate_limit
from models.UserModel import PublicUserModel, UserProfileUpdateModel
from security import CurrentUser, get_current_user

router = APIRouter(prefix="", tags=["Usuários"])

user_controller = UserController()


@router.get("/profile/{user_id}", response_model=PublicUserModel)
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
    Devolve somente o DTO público do usuário.
    """
    return user_controller.get_user_profile(user_id, current_user)


@router.put("/profile/{user_id}")
async def update_user_profile(
    user_id: int,
    data: UserProfileUpdateModel,
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
    O schema aceita somente propriedades de perfil permitidas e rejeita
    campos extras, ex:
        PUT /profile/1
        { "is_admin": true }
    retorna erro de validação e não altera propriedades privilegiadas.
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


@router.get(
    "/users",
    response_model=List[PublicUserModel],
    dependencies=[Depends(enforce_rate_limit)],
)
async def list_all_users(
    limit: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(0, ge=0, le=MAX_OFFSET),
):
    """
    API3:2023 - Excessive Data Exposure
    API9:2023 - Improper Inventory Management
    --------------------------------------------------
    Endpoint "utilitário" que ainda não exige autenticação, mas agora
    aplica paginação, limite máximo e rate limiting. A resposta é limitada
    a campos públicos; a autenticação e o inventário continuam em API9.
    """
    return user_controller.list_all_users(limit=limit, offset=offset)
