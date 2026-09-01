import json
import os
import sys
from io import BytesIO
from pathlib import Path

import urllib.request
import jwt
import pytest
from fastapi.testclient import TestClient

# Segredo exclusivo para os testes; em produção deve ser fornecido pelo
# ambiente/secret manager e nunca ficar no código da aplicação.
os.environ.setdefault(
    "JWT_SECRET_KEY",
    "test-only-secret-key-with-at-least-32-bytes",
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controllers.ProductController import ProductController
from main import app
from security import create_access_token


ProductController.initialize_database()
client = TestClient(app)


class FakeHTTPResponse:
    def __init__(self, body, status_code=200):
        self._body = body.encode("utf-8")
        self._status_code = status_code
        self.headers = {"content-type": "application/json"}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size=-1):
        return BytesIO(self._body).read(size)

    def getcode(self):
        return self._status_code


def auth_headers(user_id):
    return {"Authorization": f"Bearer {create_access_token(user_id)}"}


def test_api1_bola_rejects_another_user_profile():
    response = client.get(
        "/profile/2",
        params={"current_user_id": 2},
        headers=auth_headers(1),
    )

    assert response.status_code == 403


def test_api1_profile_uses_authenticated_identity_not_query_parameter():
    response = client.get(
        "/profile/1",
        params={"current_user_id": 2},
        headers=auth_headers(1),
    )

    assert response.status_code == 200
    assert response.json()["username"] == "alice"


def test_api1_allows_admin_to_access_another_user_profile():
    response = client.get("/profile/2", headers=auth_headers(99))

    assert response.status_code == 200
    assert response.json()["username"] == "bob"


def test_api1_bola_rejects_update_of_another_user_profile():
    response = client.put(
        "/profile/2",
        headers=auth_headers(1),
        json={"email": "attacker@example.com"},
    )

    assert response.status_code == 403


def test_api1_user_id_route_requires_object_authorization():
    unauthenticated_response = client.get("/users/1")
    assert unauthenticated_response.status_code == 401

    response = client.get("/users/2", headers=auth_headers(1))

    assert response.status_code == 403

    own_response = client.get("/users/1", headers=auth_headers(1))
    assert own_response.status_code == 200
    assert own_response.json()["username"] == "alice"
    assert set(own_response.json()) == {"id", "username"}


def test_api1_checkout_rejects_order_owned_by_another_user():
    order_id = "api1-owned-order"
    owner_response = client.post(
        "/checkout",
        headers=auth_headers(1),
        json={"order_id": order_id, "payment_method": "card"},
    )
    assert owner_response.status_code == 200

    attacker_response = client.post(
        "/checkout",
        headers=auth_headers(2),
        json={"order_id": order_id, "payment_method": "card"},
    )

    assert attacker_response.status_code == 403


def test_api2_rejects_wrong_password():
    response = client.post(
        "/login",
        json={"username": "admin", "password": "totally-wrong"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password"


def test_api2_returns_signed_expiring_token_without_sensitive_data():
    response = client.post(
        "/login",
        json={"username": "admin", "password": "admin_password"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert len(body["access_token"].split(".")) == 3
    assert "user_debug" not in body
    assert "server_secret" not in body
    assert "password" not in body

    payload = jwt.decode(
        body["access_token"],
        os.environ["JWT_SECRET_KEY"],
        algorithms=["HS256"],
        issuer="broken-api",
    )
    assert payload["sub"] == "99"
    assert "iat" in payload
    assert "exp" in payload
    assert "jti" in payload


def test_api2_rejects_tampered_token():
    response = client.post(
        "/login",
        json={"username": "alice", "password": "password123"},
    )
    token = response.json()["access_token"]
    header, payload, _signature = token.split(".")
    forged_token = f"{header}.{payload}.invalid-signature"

    from fastapi import HTTPException
    from security import decode_access_token

    with pytest.raises(HTTPException) as error:
        decode_access_token(forged_token)
    assert error.value.status_code == 401


def test_api3_rejects_profile_mass_assignment_and_filters_response():
    response = client.put(
        "/profile/1",
        headers=auth_headers(1),
        json={"is_admin": True, "password": "changed-by-client"},
    )

    assert response.status_code == 422

    safe_update = client.put(
        "/profile/1",
        headers=auth_headers(1),
        json={"email": "alice@empresa.com"},
    )
    assert safe_update.status_code == 200
    assert set(safe_update.json()) == {"id", "username"}

    profile_response = client.get("/profile/1", headers=auth_headers(1))
    assert profile_response.status_code == 200
    assert set(profile_response.json()) == {"id", "username"}


def test_api3_filters_user_collection_response():
    response = client.get("/users")

    assert response.status_code == 200
    assert response.json()
    assert all(set(user) == {"id", "username"} for user in response.json())


def test_api3_filters_product_response():
    response = client.get("/products")

    assert response.status_code == 200
    assert response.json()
    assert all(set(product) == {"id", "name", "price"} for product in response.json())


def test_api3_rejects_checkout_mass_assignment_and_filters_response():
    invalid_response = client.post(
        "/checkout",
        headers=auth_headers(1),
        json={
            "order_id": "api3-invalid-order",
            "payment_method": "card",
            "user_id": 99,
            "price": 0.01,
            "is_paid": True,
        },
    )
    assert invalid_response.status_code == 422

    valid_response = client.post(
        "/checkout",
        headers=auth_headers(1),
        json={"order_id": "api3-safe-order", "payment_method": "card"},
    )
    assert valid_response.status_code == 200
    assert set(valid_response.json()["order"]) == {"order_id", "payment_method"}

    debug_response = client.get("/checkout/debug")
    assert debug_response.status_code == 200
    assert set(debug_response.json()["all_orders"]["api3-safe-order"]) == {
        "order_id",
        "payment_method",
    }


def test_api4_products_are_paginated_and_bounded():
    default_response = client.get("/products")
    assert default_response.status_code == 200
    assert len(default_response.json()) <= 100

    page_response = client.get(
        "/products",
        params={"limit": 1, "offset": 0},
    )
    assert page_response.status_code == 200
    assert len(page_response.json()) == 1

    invalid_response = client.get("/products", params={"limit": 101})
    assert invalid_response.status_code == 422


def test_api4_user_collection_is_paginated():
    response = client.get("/users", params={"limit": 1, "offset": 0})

    assert response.status_code == 200
    assert len(response.json()) <= 1


def test_api4_product_search_is_bounded():
    response = client.get(
        "/products/search",
        params={"name": "a", "limit": 1, "offset": 0},
    )

    assert response.status_code == 200
    assert len(response.json()) <= 1


def test_api4_rejects_oversized_request_body():
    response = client.post(
        "/checkout",
        headers=auth_headers(1),
        json={
            "order_id": "api4-large-payload",
            "padding": "x" * (64 * 1024),
        },
    )

    assert response.status_code == 413


def test_api4_rate_limiter_is_enforced_on_products_route(monkeypatch):
    import limits as limits_module
    from limits import InMemoryRateLimiter

    monkeypatch.setattr(
        limits_module,
        "rate_limiter",
        InMemoryRateLimiter(max_requests=2, window_seconds=60),
    )

    responses = [client.get("/products") for _ in range(3)]

    assert [response.status_code for response in responses] == [200, 200, 429]


def test_api5_non_admin_can_change_product_price():
    response = client.put("/products/1/price", params={"new_price": -10})

    assert response.status_code == 200
    assert response.json()["new_price"] == -10


def test_api6_checkout_still_allows_business_flow_without_rate_limiting():
    response = client.post(
        "/checkout",
        headers=auth_headers(2),
        json={
            "order_id": "order-001",
            "payment_method": "card",
        },
    )

    assert response.status_code == 200


def test_api7_ssrf_fetches_user_supplied_internal_url(monkeypatch):
    captured = {}

    def fake_urlopen(url, timeout):
        captured["url"] = url
        captured["timeout"] = timeout
        return FakeHTTPResponse("cloud credentials would be here")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    metadata_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    response = client.get("/integrations/fetch-url", params={"url": metadata_url})

    assert response.status_code == 200
    assert captured["url"] == metadata_url
    assert "cloud credentials" in response.json()["body_preview"]


def test_api8_debug_endpoint_is_disabled_by_default():
    response = client.get("/auth/debug", headers={"x-lab-token": "visible"})

    assert response.status_code == 404


def test_api9_forgotten_inventory_endpoint_exposes_all_orders():
    client.post(
        "/checkout",
        headers=auth_headers(1),
        json={"order_id": "inventory-leak", "payment_method": "card"},
    )
    response = client.get("/checkout/debug")

    assert response.status_code == 200
    assert "inventory-leak" in response.json()["all_orders"]


def test_api10_unsafe_consumption_trusts_external_api_payload(monkeypatch):
    malicious_payload = {
        "street": "<script>alert('xss')</script>",
        "is_admin": True,
        "internal_risk_score": "trusted-without-validation",
    }
    captured = {}

    def fake_urlopen(url, timeout):
        captured["url"] = url
        return FakeHTTPResponse(json.dumps(malicious_payload))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    response = client.get(
        "/integrations/address/enrich",
        params={
            "zipcode": "01001000",
            "provider_url": "https://evil-provider.example/address",
        },
    )

    assert response.status_code == 200
    assert "zip=01001000" in captured["url"]
    assert response.json()["trusted_external_payload"]["is_admin"] is True
    assert response.json()["shipping_decision"]["street"].startswith("<script>")
