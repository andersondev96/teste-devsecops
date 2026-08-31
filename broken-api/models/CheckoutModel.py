"""Schemas de entrada e saída do checkout."""

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class CheckoutRequestModel(BaseModel):
    """Allowlist de dados aceitos para iniciar um checkout."""

    model_config = ConfigDict(extra="forbid")

    order_id: str = Field(min_length=1, max_length=64)
    payment_method: Optional[str] = Field(default=None, max_length=32)


class PublicOrderModel(BaseModel):
    """Representação do pedido sem proprietário ou valores internos."""

    model_config = ConfigDict(extra="forbid")

    order_id: str
    payment_method: Optional[str] = None


class CheckoutResponseModel(BaseModel):
    status: str
    order: PublicOrderModel
