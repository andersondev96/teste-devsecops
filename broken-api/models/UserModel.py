"""Schemas públicos e de entrada para operações de usuário."""

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class PublicUserModel(BaseModel):
    """Representação segura de usuário para respostas da API."""

    model_config = ConfigDict(extra="forbid")

    id: int
    username: str


class UserProfileUpdateModel(BaseModel):
    """Allowlist de propriedades que o próprio usuário pode editar."""

    model_config = ConfigDict(extra="forbid")

    username: Optional[str] = Field(default=None, min_length=1, max_length=64)
    email: Optional[str] = Field(default=None, min_length=3, max_length=254)
