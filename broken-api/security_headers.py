"""Middleware de headers seguros para respostas HTTP da API."""

from typing import Callable


class SecurityHeadersMiddleware:
    """Adiciona headers de hardening sem expor detalhes da implementação."""

    def __init__(self, app: Callable, production: bool = False):
        self.app = app
        self.production = production

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message):
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {name.lower() for name, _ in headers}

                security_headers = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"permissions-policy": b"camera=(), microphone=(), geolocation=()",
                    b"cross-origin-resource-policy": b"same-origin",
                    b"cache-control": b"no-store",
                }

                if self.production:
                    security_headers.update(
                        {
                            b"content-security-policy": b"default-src 'none'; frame-ancestors 'none'",
                            b"strict-transport-security": b"max-age=31536000; includeSubDomains",
                        }
                    )

                for name, value in security_headers.items():
                    if name not in existing:
                        headers.append((name, value))

                message["headers"] = headers

            await send(message)

        await self.app(scope, receive, send_with_security_headers)
