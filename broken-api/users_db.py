"""
ATENÇÃO — MOCK DE DADOS INTENCIONALMENTE INSEGURO
==============================================
Este arquivo simula um "banco de dados" em memória, propositalmente
malformado para fins didáticos (trabalho sobre OWASP API Security
Top 10). NÃO reflete uma modelagem de dados real ou segura.
"""

# --------------------------------------------------------------------
# API2:2023 - Broken Authentication
# Senhas armazenadas em TEXTO PURO, sem hashing (bcrypt/argon2/scrypt)
# nem salt. Se esta estrutura for um banco real e vazar (dump de BD,
# backup exposto, log acidental), todas as senhas dos usuários ficam
# imediatamente comprometidas — inclusive a de admin.
#
# API3:2023 - Excessive Data Exposure
# Campos sensíveis (senha, e-mail) ficam misturados no mesmo objeto
# que é devolvido diretamente pelas rotas da API (ver AuthController,
# UserController), sem nenhuma separação entre "dados internos" e
# "dados públicos do perfil".
#
# API5:2023 - Broken Function Level Authorization (dado de apoio)
# O campo "is_admin" booleano, exposto no mesmo objeto que qualquer
# rota devolve, facilita ataques de Mass Assignment (ver
# UserController.update_user_profile): o cliente só precisa mandar
# {"is_admin": true} no update para virar administrador.
#
# Observação adicional: o ID 99 do admin é previsível/sequencial-óbvio
# e o padrão de nomenclatura ("admin_password") é um exemplo clássico
# de senha fraca e previsível — más práticas comuns em ambientes reais
# mal configurados.
#
# Mitigação (para o trabalho):
#   - Nunca guardar senha em texto puro: usar hash forte com salt
#     (bcrypt/argon2), e nunca devolver o hash em nenhuma resposta.
#   - Separar entidade "User" (dados internos) de um DTO público
#     (ex: UserPublicProfile) que nunca inclui senha/hash, e-mail
#     completo ou flags de privilégio.
#   - Usar UUIDs não sequenciais como identificadores, dificultando
#     enumeração de IDs (mitiga parte do impacto do BOLA).
# --------------------------------------------------------------------
users_db = {
    1: {
        "id": 1,
        "username": "alice",
        "email": "alice@empresa.com",
        "is_admin": False,
        "password": "password123",  # texto puro, senha fraca
    },
    2: {
        "id": 2,
        "username": "bob",
        "email": "bob@empresa.com",
        "is_admin": False,
        "password": "password456",  # texto puro, senha fraca
    },
    99: {
        "id": 99,
        "username": "admin",
        "email": "admin@empresa.com",
        "is_admin": True,
        "password": "admin_password",  # texto puro, previsível, conta admin fácil de identificar
    },
}

# --------------------------------------------------------------------
# API4:2023 - Unrestricted Resource Consumption (dado de apoio)
# Reaproveitado por ProductController/CheckoutController: também um
# dict simples em memória, sem nenhum limite de tamanho, paginação
# ou índice — em um cenário real, cresceria sem controle.
# --------------------------------------------------------------------
checkout_db = {}
