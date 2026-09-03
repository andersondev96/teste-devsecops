"""Schemas do contrato de status OWASP fornecido pelo backend."""

from typing import List, Literal

from pydantic import BaseModel, ConfigDict, Field


OwaspStatus = Literal[
    "vulnerable",
    "partially_mitigated",
    "mitigated",
    "not_assessed",
]


class OwaspEvidenceModel(BaseModel):
    """Evidência de laboratório associada a uma categoria OWASP."""

    model_config = ConfigDict(extra="forbid")

    Title: str = Field(min_length=1)
    desc: str = Field(min_length=1)
    solution: str = Field(min_length=1)
    uri: str = Field(min_length=1)
    file: str = Field(min_length=1)
    line_number: int = Field(ge=1)


class OwaspCategoryModel(BaseModel):
    """Estado e catálogo de uma categoria OWASP do laboratório."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^API(?:[1-9]|10)$")
    title: str = Field(min_length=1)
    desc: str = Field(min_length=1)
    status: OwaspStatus
    evidence: OwaspEvidenceModel


class OwaspMetricsModel(BaseModel):
    """Métricas calculadas a partir dos estados das categorias."""

    model_config = ConfigDict(extra="forbid")

    total: int = Field(ge=0)
    mitigated: int = Field(ge=0)
    partially_mitigated: int = Field(ge=0)
    vulnerable: int = Field(ge=0)
    not_assessed: int = Field(ge=0)


class OwaspStatusResponseModel(BaseModel):
    """Contrato consumido pelo painel durante o build do frontend."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    source: Literal["backend"]
    categories: List[OwaspCategoryModel]
    metrics: OwaspMetricsModel
