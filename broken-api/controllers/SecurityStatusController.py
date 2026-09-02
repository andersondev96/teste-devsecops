"""Fonte de verdade do status OWASP publicado para o dashboard."""

import json
from collections import Counter
from pathlib import Path

from pydantic import ValidationError

from models.SecurityStatusModel import (
    OwaspCategoryModel,
    OwaspMetricsModel,
    OwaspStatusResponseModel,
)


OWASP_STATUS_FILE = Path(__file__).resolve().parents[1] / "owasp_status.json"


def get_owasp_status() -> dict:
    """Carrega, valida e calcula o contrato de status OWASP do backend."""

    try:
        with OWASP_STATUS_FILE.open(encoding="utf-8") as status_file:
            payload = json.load(status_file)

        categories = [
            OwaspCategoryModel.model_validate(category)
            for category in payload["categories"]
        ]
        counts = Counter(category.status for category in categories)
        response = OwaspStatusResponseModel(
            schema_version=payload["schema_version"],
            source=payload["source"],
            categories=categories,
            metrics=OwaspMetricsModel(
                total=len(categories),
                mitigated=counts["mitigated"],
                partially_mitigated=counts["partially_mitigated"],
                vulnerable=counts["vulnerable"],
                not_assessed=counts["not_assessed"],
            ),
        )
    except (
        OSError,
        KeyError,
        TypeError,
        ValueError,
        ValidationError,
    ) as exc:
        raise RuntimeError(
            "O contrato de status OWASP do backend está inválido."
        ) from exc

    category_ids = [category.id for category in response.categories]
    expected_ids = {f"API{index}" for index in range(1, 11)}
    if len(category_ids) != 10 or set(category_ids) != expected_ids:
        raise RuntimeError(
            "O contrato de status OWASP deve conter uma vez cada categoria API1-API10."
        )

    return response.model_dump()


def validate_owasp_status_config() -> None:
    """Falha no startup caso o status publicado esteja inconsistente."""

    get_owasp_status()
