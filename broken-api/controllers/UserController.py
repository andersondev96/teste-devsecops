"""
ATENÇÃO — CÓDIGO INTENCIONALMENTE VULNERÁVEL
==============================================
Este arquivo foi modificado APENAS para fins didáticos, como base para um
trabalho sobre identificação e mitigação de vulnerabilidades do
OWASP API Security Top 10 (2023). NÃO utilize este código em produção
ou em qualquer ambiente exposto à internet.
"""

from fastapi import HTTPException

from models.UserModel import PublicUserModel, UserProfileUpdateModel
from security import CurrentUser, authorize_object_access
from users_db import users_db


class UserController:
    def __init__(self):
        self.users_db = users_db

    def get_user_profile(self, user_id: int, current_user: CurrentUser):
        """
        API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
        --------------------------------------------------
        A identidade autenticada é recebida de uma dependência que
        valida o JWT. O acesso ao objeto é permitido apenas ao próprio
        usuário ou a um administrador; parâmetros da requisição não
        podem substituir essa identidade.

        API3:2023 - Broken Object Property Level Authorization /
        Excessive Data Exposure
        --------------------------------------------------
        A resposta usa um DTO público com somente ID e nome de usuário.
        Campos sensíveis e administrativos não são expostos.

        A autorização por objeto é aplicada antes do retorno e o registro
        bruto do banco nunca é devolvido.
        """
        authorize_object_access(current_user, user_id)

        user = self.users_db.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return PublicUserModel(
            id=user["id"],
            username=user["username"],
        ).model_dump()

    def update_user_profile(
        self,
        user_id: int,
        current_user: CurrentUser,
        data: UserProfileUpdateModel,
    ):
        """
        API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
        --------------------------------------------------
        A escrita valida a identidade autenticada contra o objeto de
        destino. Somente o próprio usuário ou um administrador pode
        alterar o perfil indicado por `user_id`.

        API3:2023 - Broken Object Property Level Authorization
        (Mass Assignment)
        --------------------------------------------------
        O schema de entrada usa uma allowlist de propriedades editáveis
        (`username` e `email`) e rejeita campos extras. Propriedades
        privilegiadas, como `is_admin`, `id` e `password_hash`, nunca são
        aplicadas ao registro.

        A autorização por objeto é aplicada antes da atualização e o
        retorno continua limitado ao DTO público.
        """
        authorize_object_access(current_user, user_id)

        user = self.users_db.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # A allowlist é definida no schema; somente campos explicitamente
        # enviados e permitidos podem ser persistidos.
        user.update(data.model_dump(exclude_unset=True, exclude_none=True))
        return PublicUserModel(
            id=user["id"],
            username=user["username"],
        ).model_dump()

    def delete_user(self, user_id: int, current_user: CurrentUser):
        """
        API5:2023 - Broken Function Level Authorization
        --------------------------------------------------
        Exclusão de conta é uma operação sensível restrita ao próprio
        usuário ou a um administrador; essa autorização é aplicada
        antes da remoção do objeto.

        Ainda é necessário registrar a operação em log de auditoria.
        """
        authorize_object_access(current_user, user_id)

        if user_id in self.users_db:
            del self.users_db[user_id]
            return {"status": "deleted", "id": user_id}
        raise HTTPException(status_code=404, detail="User not found")

    def list_all_users(self):
        """
        API3:2023 - Excessive Data Exposure
        API9:2023 - Improper Inventory Management
        --------------------------------------------------
        A rota ainda lista todos os usuários sem paginação ou autenticação
        (controles pendentes de API4/API9), mas cada item é serializado como
        um DTO público e não contém campos sensíveis.

        A mitigação da API3 consiste em devolver somente campos públicos.
        """
        return [
            PublicUserModel(
                id=user["id"],
                username=user["username"],
            ).model_dump()
            for user in self.users_db.values()
        ]
