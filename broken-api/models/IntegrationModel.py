"""Schemas para respostas controladas de provedores externos."""

from pydantic import BaseModel, ConfigDict, Field


class AddressProviderResponseModel(BaseModel):
    """Contrato estrito aceito do provedor de endereço confiável."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    street: str = Field(min_length=1, max_length=200)
    city: str = Field(min_length=1, max_length=100)
    state: str = Field(min_length=2, max_length=3, pattern=r"^[A-Za-z]{2,3}$")
    zipcode: str = Field(min_length=5, max_length=16, pattern=r"^[0-9-]+$")


class ShippingDecisionModel(BaseModel):
    """Decisão derivada localmente, sem copiar dados arbitrários externos."""

    model_config = ConfigDict(extra="forbid")

    eligible: bool
    reason: str


class AddressEnrichmentResponseModel(BaseModel):
    """Resposta pública sem payload bruto ou propriedades inesperadas."""

    model_config = ConfigDict(extra="forbid")

    provider: str
    zipcode: str
    address: AddressProviderResponseModel
    shipping_decision: ShippingDecisionModel
