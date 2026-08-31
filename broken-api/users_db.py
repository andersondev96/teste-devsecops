"""Base de dados em memória usada pelo laboratório local."""

# --------------------------------------------------------------------
# API2:2023 - Broken Authentication
# As senhas não são mantidas em texto puro. Os valores abaixo são hashes
# scrypt com salt individual. Em uma aplicação real, a migração deve ser
# executada fora do código e os hashes devem ficar em um banco protegido.
#
# API3:2023 - Excessive Data Exposure
# Campos sensíveis (senha, e-mail) permanecem somente no modelo interno.
# As rotas usam schemas de saída explícitos e nunca devolvem estes objetos
# diretamente ao cliente.
#
# API5:2023 - Broken Function Level Authorization (dado de apoio)
# O campo "is_admin" deve ser lido somente no servidor e nunca aceito em
# atualizações provenientes do cliente.
#
# Observação adicional: o ID 99 do admin é previsível/sequencial-óbvio
# e o padrão de nomenclatura ("admin_password") é um exemplo clássico
# de senha fraca e previsível — más práticas comuns em ambientes reais
# mal configurados.
#
# Os dados internos não devem ser devolvidos diretamente por endpoints.
# --------------------------------------------------------------------
users_db = {
    1: {
        "id": 1,
        "username": "alice",
        "email": "alice@empresa.com",
        "is_admin": False,
        "password_hash": "scrypt$16384$8$1$eWozkSRLwIdibYiz3l_N_A$ySq1qI6mSodtBlUlJ-YkwlQv5gNrvhrIHA3lEV7dYQiFuYPNh8XY1I3A332b0Dp994AOcIeHmC54DDyqJRcuSg",  # nosec B105
    },
    2: {
        "id": 2,
        "username": "bob",
        "email": "bob@empresa.com",
        "is_admin": False,
        "password_hash": "scrypt$16384$8$1$xjDluLCH3A0KJKyJCDhogw$g_4HKOZw34UHIffxjcKBMXp4jxlQmbltaJZCo4u1yiT36fxM_HE2ggFRy4jZIM10n8OcCF7wpUMmETcEHlS1BQ",  # nosec B105
    },
    99: {
        "id": 99,
        "username": "admin",
        "email": "admin@empresa.com",
        "is_admin": True,
        "password_hash": "scrypt$16384$8$1$W3lHL4bY5yMGIGz7Nv9i2w$yRj2z--h3oKu2wvAGsCXt869GE6fKk6W516vB76Je_OXzWlxPhcjTYKPhy2rMLgLr_IzF05l_jrPsd470V0C6g",  # nosec B105
    },
}

# --------------------------------------------------------------------
# API4:2023 - Unrestricted Resource Consumption (dado de apoio)
# Reaproveitado por ProductController/CheckoutController: também um
# dict simples em memória, sem nenhum limite de tamanho, paginação
# ou índice — em um cenário real, cresceria sem controle.
# --------------------------------------------------------------------
checkout_db = {}
