"""Integrações externas usadas no laboratório OWASP API Security Top 10 2023."""

import http.client
import ipaddress
import json
import os
import socket
import ssl
import urllib.parse
import urllib.request
from dataclasses import dataclass

from fastapi import HTTPException, status
from pydantic import ValidationError

from models.IntegrationModel import AddressProviderResponseModel


DEFAULT_ADDRESS_PROVIDER_URL = "https://address-provider.example.com/address"
DEFAULT_ADDRESS_PROVIDER_ALLOWED_HOST = "address-provider.example.com"
DEFAULT_REMOTE_FETCH_ALLOWED_HOST = "api.example.com"
EXTERNAL_REQUEST_TIMEOUT_SECONDS = 3
MAX_EXTERNAL_RESPONSE_BYTES = 16 * 1024
MAX_REMOTE_FETCH_BODY_BYTES = 2 * 1024


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


def _allowed_remote_fetch_hosts() -> set[str]:
    configured_hosts = os.getenv(
        "API7_ALLOWED_HOSTS",
        DEFAULT_REMOTE_FETCH_ALLOWED_HOST,
    )
    hosts = {
        host.strip().lower().rstrip(".")
        for host in configured_hosts.split(",")
        if host.strip()
    }

    if not hosts or any("*" in host for host in hosts):
        raise RuntimeError(
            "API7_ALLOWED_HOSTS deve conter hosts exatos e não pode usar wildcard."
        )

    return hosts


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
    _allowed_remote_fetch_hosts()


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


def _remote_url_not_allowed() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        detail="URL de destino não permitida",
    )


def _remote_fetch_bad_gateway() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail="Falha ao consultar o destino autorizado",
    )


def _resolve_public_ip(hostname: str, port: int) -> str:
    """Resolve o host e rejeita qualquer endereço que não seja global."""

    try:
        literal_ip = ipaddress.ip_address(hostname)
        addresses = [literal_ip]
    except ValueError:
        try:
            address_info = socket.getaddrinfo(
                hostname,
                port,
                type=socket.SOCK_STREAM,
            )
        except (OSError, socket.gaierror) as exc:
            raise _remote_url_not_allowed() from exc

        addresses = []
        for item in address_info:
            try:
                addresses.append(ipaddress.ip_address(item[4][0].split("%", 1)[0]))
            except (IndexError, ValueError):
                continue

    if not addresses or any(not address.is_global for address in addresses):
        # Bloqueia redes privadas, loopback, link-local, multicast,
        # reservadas e não especificadas, inclusive em IPv6.
        raise _remote_url_not_allowed()

    return str(addresses[0])


@dataclass(frozen=True)
class _ValidatedRemoteTarget:
    url: str
    hostname: str
    resolved_ip: str
    request_path: str


def _validate_remote_target(url: str) -> _ValidatedRemoteTarget:
    """Valida o destino antes de qualquer conexão de rede."""

    try:
        parsed_url = urllib.parse.urlsplit(url.strip())
        hostname = parsed_url.hostname
        port = parsed_url.port
    except (AttributeError, ValueError) as exc:
        raise _remote_url_not_allowed() from exc

    normalized_hostname = hostname.lower().rstrip(".") if hostname else None
    if (
        parsed_url.scheme.lower() != "https"
        or not normalized_hostname
        or normalized_hostname not in _allowed_remote_fetch_hosts()
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.fragment
        or port not in (None, 443)
    ):
        raise _remote_url_not_allowed()

    resolved_ip = _resolve_public_ip(normalized_hostname, 443)
    request_path = parsed_url.path or "/"
    if parsed_url.query:
        request_path = f"{request_path}?{parsed_url.query}"

    return _ValidatedRemoteTarget(
        url=parsed_url.geturl(),
        hostname=normalized_hostname,
        resolved_ip=resolved_ip,
        request_path=request_path,
    )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Conecta ao IP validado mantendo o hostname para TLS/SNI."""

    def __init__(self, hostname: str, resolved_ip: str, timeout: int):
        super().__init__(
            hostname,
            port=443,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        self._resolved_ip = resolved_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._resolved_ip, self.port),
            self.timeout,
        )
        self.sock = self._context.wrap_socket(
            self.sock,
            server_hostname=self.host,
        )


class _RemoteHTTPResponse:
    """Pequeno adaptador para manter a interface usada pela camada de serviço."""

    def __init__(self, connection, response):
        self._connection = connection
        self._response = response
        self.headers = response.headers

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()
        return False

    def read(self, size=-1):
        return self._response.read(size)

    def getcode(self):
        return self._response.status

    def close(self):
        self._response.close()
        self._connection.close()


def _open_safe_remote_url(
    target: _ValidatedRemoteTarget,
    timeout: int = EXTERNAL_REQUEST_TIMEOUT_SECONDS,
):
    """Faz somente GET HTTPS ao IP já validado, sem seguir redirects."""

    connection = _PinnedHTTPSConnection(
        target.hostname,
        target.resolved_ip,
        timeout,
    )
    try:
        connection.request(
            "GET",
            target.request_path,
            headers={
                "Accept": "application/json, text/plain",
                "Host": target.hostname,
            },
        )
        return _RemoteHTTPResponse(connection, connection.getresponse())
    except Exception:
        connection.close()
        raise

class IntegrationController:
    @staticmethod
    def fetch_remote_url(url: str):
        """
        API7:2023 - Server Side Request Forgery (SSRF)
        --------------------------------------------------
        A URL do cliente só é aceita quando usa HTTPS, pertence à allowlist
        exata, resolve para um IP global e usa a porta 443. O IP validado é
        fixado na conexão para reduzir o risco de DNS rebinding. A conexão
        não segue redirects, tem timeout e limita o corpo retornado.
        """
        target = _validate_remote_target(url)

        try:
            with _open_safe_remote_url(
                target,
                timeout=EXTERNAL_REQUEST_TIMEOUT_SECONDS,
            ) as response:
                status_code = response.getcode()
                if 300 <= status_code < 400:
                    raise _remote_fetch_bad_gateway()

                raw_body = response.read(MAX_REMOTE_FETCH_BODY_BYTES + 1)
                if len(raw_body) > MAX_REMOTE_FETCH_BODY_BYTES:
                    raise _remote_fetch_bad_gateway()

                content_type = str(
                    response.headers.get("content-type", "")
                ).split(";", 1)[0].strip().lower()
                body = raw_body.decode("utf-8", errors="replace")
        except HTTPException:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError, UnicodeError) as exc:
            raise _remote_fetch_bad_gateway() from exc

        return {
            "requested_url": target.url,
            "status_code": status_code,
            "content_type": content_type,
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
