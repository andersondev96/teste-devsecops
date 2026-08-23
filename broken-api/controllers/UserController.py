"""
ATENÇÃO — CÓDIGO INTENCIONALMENTE VULNERÁVEL
==============================================
Este arquivo foi modificado APENAS para fins didáticos, como base para um
trabalho sobre identificação e mitigação de vulnerabilidades do
OWASP API Security Top 10 (2023). NÃO utilize este código em produção
ou em qualquer ambiente exposto à internet.
"""

from fastapi import HTTPException

from users_db import users_db


class UserController:
    def __init__(self):
        self.users_db = users_db

    def get_user_profile(self, user_id: int, current_user_id: int):
        """
        API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
        --------------------------------------------------
        O parâmetro `current_user_id` é recebido mas NUNCA é usado
        para validar se o usuário autenticado tem permissão de ver o
        perfil de `user_id`. Ou seja, qualquer usuário logado (o
        parâmetro só existe de fachada) pode consultar o perfil de
        QUALQUER outra pessoa apenas trocando o ID na URL/requisição.

        API3:2023 - Broken Object Property Level Authorization /
        Excessive Data Exposure
        --------------------------------------------------
        O objeto inteiro do usuário é devolvido sem filtrar campos
        sensíveis (senha/hash, e-mail, dados de pagamento, tokens
        internos), quando o solicitante provavelmente só deveria ver
        um subconjunto público do perfil (nome, avatar, bio).

        Mitigação (para o trabalho):
            if user_id != current_user_id and not is_admin(current_user_id):
                raise HTTPException(status_code=403, detail="Forbidden")
        e usar um schema de saída (Pydantic) que exponha só campos
        públicos, nunca o registro bruto do banco.
        """
        user = self.users_db.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # BOLA: `current_user_id` chega como parâmetro mas é ignorado
        # por completo — nenhuma comparação com `user_id` é feita.
        return user

    def update_user_profile(self, user_id: int, current_user_id: int, data: dict):
        """
        API1:2023 - Broken Object Level Authorization (BOLA/IDOR)
        --------------------------------------------------
        Assim como na leitura, a escrita também ignora
        `current_user_id`: qualquer usuário autenticado pode alterar
        o perfil de QUALQUER outro usuário só informando o `user_id`
        de destino.

        API3:2023 - Broken Object Property Level Authorization
        (Mass Assignment)
        --------------------------------------------------
        `data` é aplicado inteiro sobre o registro do usuário sem
        nenhuma lista de campos permitidos. Isso permite que o cliente
        envie, por exemplo, { "role": "admin", "is_verified": True,
        "balance": 999999 } e o servidor aceite cegamente, promovendo
        um usuário comum a administrador ou adulterando saldo.

        Mitigação: validar `user_id == current_user_id` (ou permissão
        de admin), e usar um schema de entrada com allowlist explícita
        de campos editáveis (ex: nome, bio, avatar — nunca role/saldo).
        """
        user = self.users_db.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Mass Assignment: qualquer chave do dict `data` sobrescreve o
        # registro do usuário, incluindo campos privilegiados.
        user.update(data)
        return user

    def delete_user(self, user_id: int, current_user_id: int):
        """
        API5:2023 - Broken Function Level Authorization
        --------------------------------------------------
        Exclusão de conta é uma operação sensível que deveria ser
        restrita ao próprio usuário ou a um admin. Aqui não há
        nenhuma checagem de papel (role) nem comparação com
        `current_user_id` — qualquer chamador autenticado apaga
        qualquer conta do sistema.

        Mitigação: exigir que `current_user_id == user_id` OU que o
        usuário autenticado tenha role "admin"; registrar a operação
        em log de auditoria.
        """
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