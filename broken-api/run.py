# Executar aplicação
if __name__ == "__main__":
    import os
    import secrets
    import sys

    if sys.version_info < (3, 10):
        raise RuntimeError(
            "A API requer Python 3.10 ou superior para usar dependências "
            "com correções de segurança suportadas."
        )

    import uvicorn

    # `python run.py` é o executor de desenvolvimento. Quando nenhuma chave
    # foi configurada localmente, cria uma chave efêmera apenas para essa
    # sessão, sem gravá-la no código ou no repositório.
    # Em produção a configuração continua obrigatória e é validada por
    # `security.validate_security_config()`.
    app_environment = os.getenv("APP_ENV", "development").strip().lower()
    if not os.getenv("JWT_SECRET_KEY") and app_environment not in {"prod", "production"}:
        os.environ["JWT_SECRET_KEY"] = secrets.token_urlsafe(32)
        print("JWT_SECRET_KEY não definida; foi gerada uma chave efêmera para o ambiente local.")

    # O bind em todas as interfaces é necessário para o encaminhamento Docker.
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)  # nosec B104
