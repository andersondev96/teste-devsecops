"""Schemas de entrada e saída do checkout."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from limits import MAX_CHECKOUT_QUANTITY


class CheckoutRequestModel(BaseModel):
    """Allowlist de dados necessários para concluir uma compra."""

    model_config = ConfigDict(extra="forbid")

    order_id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$",
    )
    product_id: int = Field(gt=0)
    quantity: int = Field(ge=1, le=MAX_CHECKOUT_QUANTITY)
    payment_method: Literal["card", "pix", "boleto"]


class PublicOrderModel(BaseModel):
    """Representação pública do pedido sem proprietário ou campos internos."""

    model_config = ConfigDict(extra="forbid")

    order_id: str
    product_id: int
    quantity: int
    payment_method: Literal["card", "pix", "boleto"]
    total: float
    status: Literal["completed"]


class CheckoutResponseModel(BaseModel):
    status: str
    order: PublicOrderModel


class AdminOrderModel(BaseModel):
    """Representação do inventário disponível somente para administradores."""

    model_config = ConfigDict(extra="forbid")

    order_id: str
    user_id: int
    product_id: int
    quantity: int
    payment_method: Literal["card", "pix", "boleto"]
    total: float
    status: Literal["completed"]
