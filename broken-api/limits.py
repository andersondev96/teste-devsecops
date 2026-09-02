"""Controles compartilhados contra consumo irrestrito de recursos."""

from collections import OrderedDict, deque
from threading import Lock
from time import monotonic
from typing import Callable, Deque

from fastapi import HTTPException, Request, status


DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 100
MAX_OFFSET = 1_000_000
MAX_REQUEST_BODY_BYTES = 64 * 1024
RATE_LIMIT_REQUESTS = 60
RATE_LIMIT_WINDOW_SECONDS = 60.0
MAX_RATE_LIMIT_KEYS = 10_000
BUSINESS_FLOW_RATE_LIMIT_REQUESTS = 5
BUSINESS_FLOW_RATE_LIMIT_WINDOW_SECONDS = 60.0
MAX_CHECKOUT_QUANTITY = 10
MAX_CHECKOUT_TOTAL = 100_000.0
MAX_PRODUCT_PRICE = 1_000_000.0


class InMemoryRateLimiter:
    """Rate limiter local com janela fixa e quantidade de chaves limitada."""

    def __init__(self, max_requests: int, window_seconds: float):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._windows: "OrderedDict[str, Deque[float]]" = OrderedDict()
        self._lock = Lock()

    def check(self, key: str) -> None:
        now = monotonic()

        with self._lock:
            timestamps = self._windows.get(key)
            if timestamps is None:
                timestamps = deque()
                self._windows[key] = timestamps
            else:
                self._windows.move_to_end(key)

            cutoff = now - self.window_seconds
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()

            if len(timestamps) >= self.max_requests:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests",
                    headers={"Retry-After": str(int(self.window_seconds))},
                )

            timestamps.append(now)

            # Evita que um atacante crie um dicionário ilimitado de chaves
            # usando endereços ou identificadores diferentes.
            while len(self._windows) > MAX_RATE_LIMIT_KEYS:
                self._windows.popitem(last=False)


rate_limiter = InMemoryRateLimiter(
    max_requests=RATE_LIMIT_REQUESTS,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)

business_flow_limiter = InMemoryRateLimiter(
    max_requests=BUSINESS_FLOW_RATE_LIMIT_REQUESTS,
    window_seconds=BUSINESS_FLOW_RATE_LIMIT_WINDOW_SECONDS,
)


def enforce_rate_limit(request: Request) -> None:
    """Limita chamadas por origem e rota para endpoints de maior custo."""

    client_host = request.client.host if request.client else "unknown"
    rate_limiter.check(f"{client_host}:{request.url.path}")


def enforce_business_flow_limit(user_id: int) -> None:
    """Limita tentativas de fluxo sensível por identidade autenticada."""

    business_flow_limiter.check(f"user:{user_id}")


class RequestBodyTooLarge(Exception):
    """Sinaliza que o corpo excedeu o limite antes do parsing da aplicação."""


class RequestBodySizeLimitMiddleware:
    """Limita corpos declarados e também requisições em chunks."""

    def __init__(self, app: Callable, max_body_bytes: int = MAX_REQUEST_BODY_BYTES):
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        raw_content_length = headers.get(b"content-length")
        if raw_content_length:
            try:
                if int(raw_content_length) > self.max_body_bytes:
                    await self._send_rejection(send)
                    return
            except ValueError:
                # O tamanho será controlado durante a leitura dos chunks.
                pass

        received_bytes = 0
        response_started = False

        async def limited_receive():
            nonlocal received_bytes
            message = await receive()
            if message.get("type") == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > self.max_body_bytes:
                    raise RequestBodyTooLarge()
            return message

        async def tracked_send(message):
            nonlocal response_started
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except RequestBodyTooLarge:
            if not response_started:
                await self._send_rejection(send)

    async def _send_rejection(self, send):
        body = b'{"detail":"Request body too large"}'
        await send(
            {
                "type": "http.response.start",
                "status": status.HTTP_413_CONTENT_TOO_LARGE,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
