"""
ATENÇÃO — CÓDIGO INTENCIONALMENTE VULNERÁVEL
==============================================
Este arquivo foi modificado APENAS para fins didáticos, como base para um
trabalho sobre identificação e mitigação de vulnerabilidades do
OWASP API Security Top 10 (2023). NÃO utilize este código em produção
ou em qualquer ambiente exposto à internet.
"""

from fastapi import HTTPException

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
        O objeto inteiro do usuário é devolvido sem filtrar campos
        sensíveis (senha/hash, e-mail, dados de pagamento, tokens
        internos), quando o solicitante provavelmente só deveria ver
        um subconjunto público do perfil (nome, avatar, bio).

        A autorização por objeto é aplicada antes do retorno. Ainda é
        necessário usar um schema de saída (Pydantic) que exponha só campos
        públicos, nunca o registro bruto do banco.
        """
        authorize_object_access(current_user, user_id)

        user = self.users_db.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return user

    def update_user_profile(self, user_id: int, current_user: CurrentUser, data: dict):
        """
        API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
        --------------------------------------------------
        A escrita valida a identidade autenticada contra o objeto de
        destino. Somente o próprio usuário ou um administrador pode
        alterar o perfil indicado por `user_id`.

        API3:2023 - Broken Object Property Level Authorization
        (Mass Assignment)
        --------------------------------------------------
        `data` é aplicado inteiro sobre o registro do usuário sem
        nenhuma lista de campos permitidos. Isso permite que o cliente
        envie, por exemplo, { "role": "admin", "is_verified": True,
        "balance": 999999 } e o servidor aceite cegamente, promovendo
        um usuário comum a administrador ou adulterando saldo.

        A autorização por objeto já foi aplicada. Ainda é necessário
        usar um schema de entrada com allowlist explícita
        de campos editáveis (ex: nome, bio, avatar — nunca role/saldo).
        """
        authorize_object_access(current_user, user_id)

        user = self.users_db.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Mass Assignment: qualquer chave do dict `data` sobrescreve o
        # registro do usuário, incluindo campos privilegiados.
        user.update(data)
        return user

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
        Rota "utilitária" que devolve a base de usuários inteira, sem
        paginação, sem autenticação e sem filtrar campos sensíveis —
        um vazamento completo de PII (dados pessoais) em uma única
        chamada. Endpoints assim costumam ser criados para debug e
        esquecidos em produção.

        Mitigação: remover este endpoint de produção, ou, se
        necessário, restringi-lo a admins, paginar os resultados e
        devolver apenas campos públicos de cada usuário.
        """
        return list(self.users_db.values())
