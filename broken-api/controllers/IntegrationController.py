"""
Integrações externas usadas no laboratório OWASP API Security Top 10 2023.

O endpoint de SSRF (API7) permanece intencionalmente vulnerável para fins
didáticos. O fluxo de enriquecimento de endereço aplica os controles de
API10: provedor fixo, allowlist, HTTPS, timeout, limite de resposta e
validação estrita do contrato externo.
"""

import json
import os
import urllib.parse
import urllib.request

from fastapi import HTTPException, status
from pydantic import ValidationError

from models.IntegrationModel import AddressProviderResponseModel


DEFAULT_ADDRESS_PROVIDER_URL = "https://address-provider.example.com/address"
DEFAULT_ADDRESS_PROVIDER_ALLOWED_HOST = "address-provider.example.com"
EXTERNAL_REQUEST_TIMEOUT_SECONDS = 3
MAX_EXTERNAL_RESPONSE_BYTES = 16 * 1024


def _allowed_provider_hosts() -> set[str]:
    configured_hosts = os.getenv(
        "ADDRESS_PROVIDER_ALLOWED_HOSTS",
        DEFAULT_ADDRESS_PROVIDER_ALLOWED_HOST,
    )
    return {
        host.strip().lower()
        for host in configured_hosts.split(",")
        if host.strip()
    }


def _trusted_address_provider_url() -> str:
    provider_url = os.getenv(
        "ADDRESS_PROVIDER_URL",
        DEFAULT_ADDRESS_PROVIDER_URL,
    ).strip()
    parsed_url = urllib.parse.urlparse(provider_url)

    try:
        provider_hostname = parsed_url.hostname
        provider_port = parsed_url.port
    except ValueError as exc:
        raise RuntimeError(
            "ADDRESS_PROVIDER_URL deve usar um host e porta HTTPS válidos."
        ) from exc

    if (
        parsed_url.scheme.lower() != "https"
        or provider_hostname is None
        or provider_hostname.lower() not in _allowed_provider_hosts()
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.query
        or parsed_url.fragment
        or provider_port not in (None, 443)
    ):
        raise RuntimeError(
            "ADDRESS_PROVIDER_URL deve ser HTTPS e pertencer à allowlist configurada."
        )

    return provider_url.rstrip("/")


def validate_integration_config() -> None:
    """Valida a configuração do provedor externo antes de iniciar a API."""

    _trusted_address_provider_url()


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Impede que o provedor redirecione a integração para outro destino."""

    def redirect_request(self, request, *args, **kwargs):
        return None


def _open_trusted_provider(
    target: str,
    timeout: int = EXTERNAL_REQUEST_TIMEOUT_SECONDS,
):
    opener = urllib.request.build_opener(_NoRedirectHandler)
    request = urllib.request.Request(
        target,
        headers={"Accept": "application/json"},
        method="GET",
    )
    return opener.open(request, timeout=timeout)


def _external_bad_gateway():
    return HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail="Resposta inválida do provedor externo",
    )

class IntegrationController:
    @staticmethod
    def fetch_remote_url(url: str):
        """
        API7:2023 - Server Side Request Forgery (SSRF)
        --------------------------------------------------
        A URL vem diretamente do cliente e o servidor faz a requisicao
        sem validar esquema, host, porta, rede privada, redirecionamento
        ou destino final. Isso permite que um atacante faca o servidor
        acessar recursos internos como:

            http://169.254.169.254/latest/meta-data/
            http://localhost:8000/auth/debug
            http://127.0.0.1:2375/containers/json

        Mitigacao: allowlist de dominios confiaveis, bloqueio de redes
        privadas/link-local/localhost, limite de redirects, timeout curto
        e isolamento do componente que faz chamadas externas.
        """
        with urllib.request.urlopen(url, timeout=3) as response:  # nosec - laboratorio vulneravel
            body = response.read(2048).decode("utf-8", errors="replace")
            return {
                "requested_url": url,
                "status_code": response.getcode(),
                "headers": dict(response.headers),
                "body_preview": body,
            }

    @staticmethod
    def enrich_address(zipcode: str):
        """
        API10:2023 - Unsafe Consumption of APIs
        --------------------------------------------------
        Consome apenas o provedor HTTPS configurado no servidor. A resposta
        precisa ser JSON, respeitar o limite de tamanho e obedecer ao schema
        estrito antes de participar da decisão de negócio.
        """
        provider_url = _trusted_address_provider_url()
        query = urllib.parse.urlencode({"zip": zipcode})
        target = f"{provider_url}?{query}"

        try:
            with _open_trusted_provider(
                target,
                timeout=EXTERNAL_REQUEST_TIMEOUT_SECONDS,
            ) as response:
                content_type = str(
                    response.headers.get("content-type", "")
                ).split(";", 1)[0].strip().lower()
                if content_type != "application/json":
                    raise _external_bad_gateway()

                raw_body = response.read(MAX_EXTERNAL_RESPONSE_BYTES + 1)
                if len(raw_body) > MAX_EXTERNAL_RESPONSE_BYTES:
                    raise _external_bad_gateway()

                external_payload = json.loads(raw_body.decode("utf-8"))
                address = AddressProviderResponseModel.model_validate(
                    external_payload
                )
                if address.zipcode != zipcode:
                    raise _external_bad_gateway()
        except HTTPException:
            raise
        except (OSError, TypeError, UnicodeError, ValidationError, ValueError) as exc:
            raise _external_bad_gateway() from exc

        return {
            "provider": provider_url,
            "zipcode": zipcode,
            "address": address.model_dump(),
            "shipping_decision": {
                "eligible": True,
                "reason": "validated_provider_response",
            },
        }
