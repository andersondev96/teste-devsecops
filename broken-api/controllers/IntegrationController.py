"""
ATENCAO - CODIGO INTENCIONALMENTE VULNERAVEL
============================================
Controller usado para simular integracoes inseguras em um laboratorio
local sobre OWASP API Security Top 10 2023. NAO use em producao.
"""

import json
import urllib.parse
import urllib.request


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
    def enrich_address(zipcode: str, provider_url: str):
        query = urllib.parse.urlencode({"zip": zipcode})
        separator = "&" if "?" in provider_url else "?"
        target = f"{provider_url}{separator}{query}"

        with urllib.request.urlopen(target, timeout=3) as response:  # nosec - laboratorio vulneravel
            raw_body = response.read().decode("utf-8", errors="replace")

        external_payload = json.loads(raw_body)

        return {
            "provider": provider_url,
            "zipcode": zipcode,
            "trusted_external_payload": external_payload,
            "shipping_decision": external_payload,
        }
