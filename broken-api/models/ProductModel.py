"""Schemas públicos do catálogo de produtos."""

from pydantic import BaseModel, ConfigDict


class PublicProductModel(BaseModel):
    """Somente propriedades necessárias para exibir o catálogo."""

    model_config = ConfigDict(extra="forbid")

    id: int
    name: str
    price: float
