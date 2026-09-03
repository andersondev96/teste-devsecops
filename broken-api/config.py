"""Configurações de ambiente relacionadas ao hardening da aplicação."""

from typing import Optional


PRODUCTION_ENVIRONMENTS = {"prod", "production"}


def is_production_environment(environment: str) -> bool:
    """Retorna se o ambiente deve receber as restrições de produção."""

    return environment.strip().lower() in PRODUCTION_ENVIRONMENTS


def docs_are_enabled(environment: str, configured_value: Optional[str] = None) -> bool:
    """Define se o OpenAPI/Swagger deve ser publicado nesse ambiente.

    A documentação é permitida por padrão em desenvolvimento e CI para
    apoiar o laboratório e o DAST. Em produção ela fica sempre desativada,
    mesmo que alguém tente habilitá-la por variável de ambiente.
    """

    if is_production_environment(environment):
        return False

    if configured_value is None:
        return True

    return configured_value.strip().lower() in {"1", "true", "yes", "on"}
