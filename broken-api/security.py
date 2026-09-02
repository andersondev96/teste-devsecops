"""
Componentes compartilhados de autenticação.

Este módulo concentra a criação/verificação de hashes de senha e de tokens
JWT, além das primitivas compartilhadas de autorização. A identidade usada
pelas rotas é obtida de um token validado, e não de parâmetros controlados
pelo cliente.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from users_db import users_db


JWT_ALGORITHM = "HS256"
JWT_ISSUER = os.getenv("JWT_ISSUER", "broken-api")
# Nome da variável de ambiente; não é um segredo embutido no código.
JWT_SECRET_ENV = "JWT_SECRET_KEY"  # nosec B105

# Os limites evitam que um hash armazenado de forma inválida provoque um
# consumo arbitrário de recursos durante a autenticação.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 64
SCRYPT_MAXMEM = 64 * 1024 * 1024

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class CurrentUser:
    """Identidade mínima e não sensível disponibilizada às rotas."""

    id: int
    username: str
    is_admin: bool


def authorize_object_access(current_user: CurrentUser, object_owner_id: int) -> None:
    """Garante acesso ao objeto somente ao dono ou a um administrador."""

    if current_user.is_admin or current_user.id == object_owner_id:
        return

    # Não informa se o objeto pertence a outro usuário.
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def authorize_admin(current_user: CurrentUser) -> None:
    """Garante que a identidade autenticada possui função administrativa."""

    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator role required",
        )


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def hash_password(password: str) -> str:
    """Gera um hash scrypt com salt aleatório e parâmetros explícitos."""

    salt = secrets.token_bytes(16)
    derived_key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )
    return "$".join(
        (
            "scrypt",
            str(SCRYPT_N),
            str(SCRYPT_R),
            str(SCRYPT_P),
            _b64encode(salt),
            _b64encode(derived_key),
        )
    )


def verify_password(password: str, encoded_hash: Optional[str]) -> bool:
    """Verifica um hash scrypt sem aceitar o formato legado em texto puro."""

    if not encoded_hash:
        return False

    try:
        algorithm, n_text, r_text, p_text, salt_text, digest_text = encoded_hash.split("$")
        n = int(n_text)
        r = int(r_text)
        p = int(p_text)

        # Somente parâmetros dentro da política local são aceitos.
        if algorithm != "scrypt":
            return False
        if not 2**14 <= n <= 2**16 or not 1 <= r <= 8 or not 1 <= p <= 4:
            return False

        salt = _b64decode(salt_text)
        expected_digest = _b64decode(digest_text)
        if not 16 <= len(salt) <= 64 or len(expected_digest) != SCRYPT_DKLEN:
            return False

        derived_key = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=len(expected_digest),
            maxmem=SCRYPT_MAXMEM,
        )
        return hmac.compare_digest(derived_key, expected_digest)
    except (TypeError, ValueError, UnicodeError):
        # Hashes malformados nunca devem causar erro 500 nem permitir login.
        return False


# Hash usado apenas para manter aproximadamente o mesmo custo quando o
# username não existe. O valor nunca representa uma credencial válida.
DUMMY_PASSWORD_HASH = hash_password("dummy-password-not-used")


def _jwt_secret_key() -> str:
    secret_key = os.getenv(JWT_SECRET_ENV, "")
    if len(secret_key.encode("utf-8")) < 32:
        raise RuntimeError(
            f"A variável {JWT_SECRET_ENV} deve conter pelo menos 32 bytes."
        )
    return secret_key


def _access_token_expire_minutes() -> int:
    raw_value = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15")
    try:
        minutes = int(raw_value)
    except ValueError as exc:
        raise RuntimeError("ACCESS_TOKEN_EXPIRE_MINUTES deve ser um inteiro.") from exc

    if not 5 <= minutes <= 60:
        raise RuntimeError("ACCESS_TOKEN_EXPIRE_MINUTES deve estar entre 5 e 60.")
    return minutes


def validate_security_config() -> None:
    """Falha no startup quando a configuração mínima não está presente."""

    _jwt_secret_key()
    _access_token_expire_minutes()


def create_access_token(user_id: int) -> str:
    """Cria um JWT curto, assinado e com claims mínimas."""

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=_access_token_expire_minutes())
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": expires_at,
        "iss": JWT_ISSUER,
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, _jwt_secret_key(), algorithm=JWT_ALGORITHM)


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def decode_access_token(token: str) -> dict:
    """Valida assinatura, algoritmo, emissor e claims obrigatórias do JWT."""

    try:
        return jwt.decode(
            token,
            _jwt_secret_key(),
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            options={"require": ["sub", "iat", "exp", "iss", "jti"]},
        )
    except (jwt.PyJWTError, RuntimeError, ValueError):
        raise _unauthorized()


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> CurrentUser:
    """Dependência FastAPI que resolve a identidade a partir do Bearer token."""

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _unauthorized()

    payload = decode_access_token(credentials.credentials)
    subject = payload.get("sub")
    try:
        user_id = int(subject)
    except (TypeError, ValueError):
        raise _unauthorized()

    user = users_db.get(user_id)
    if not user:
        raise _unauthorized()

    return CurrentUser(
        id=user["id"],
        username=user["username"],
        # O papel é carregado da fonte confiável no servidor, não do token
        # nem do corpo da requisição.
        is_admin=bool(user.get("is_admin", False)),
    )


def require_admin(
    current_user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """Dependência para endpoints cuja função é exclusivamente administrativa."""

    authorize_admin(current_user)
    return current_user
