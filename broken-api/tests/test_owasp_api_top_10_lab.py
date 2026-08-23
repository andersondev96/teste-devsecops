import json
import sys
from io import BytesIO
from pathlib import Path

import urllib.request
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from controllers.ProductController import ProductController
from main import app


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


def test_api1_bola_reads_another_user_profile():
    response = client.get("/profile/2", params={"current_user_id": 1})

    assert response.status_code == 200
    assert response.json()["username"] == "bob"


def test_api2_broken_authentication_accepts_wrong_password():
    response = client.post(
        "/login",
        json={"username": "admin", "password": "totally-wrong"},
    )

    assert response.status_code == 200
    assert response.json()["access_token"]
    assert response.json()["user_debug"]["password"] == "admin_password"


def test_api3_mass_assignment_changes_privileged_property():
    response = client.put(
        "/profile/1",
        params={"current_user_id": 1},
        json={"is_admin": True, "password": "changed-by-client"},
    )

    assert response.status_code == 200
    assert response.json()["is_admin"] is True
    assert response.json()["password"] == "changed-by-client"


def test_api4_products_are_returned_without_pagination_or_limit():
    response = client.get("/products")

    assert response.status_code == 200
    assert len(response.json()) >= 3


def test_api5_non_admin_can_change_product_price():
    response = client.put("/products/1/price", params={"new_price": -10})

    assert response.status_code == 200
    assert response.json()["new_price"] == -10


def test_api6_checkout_accepts_sensitive_business_flow_abuse():
    response = client.post(
        "/checkout",
        json={
            "order_id": "order-001",
            "user_id": 2,
            "price": 0.01,
            "discount": 99,
            "is_paid": True,
        },
    )

    assert response.status_code == 200
    assert response.json()["order"]["price"] == 0.01
    assert response.json()["order"]["is_paid"] is True


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


def test_api8_debug_endpoint_exposes_secrets_and_headers():
    response = client.get("/auth/debug", headers={"x-lab-token": "visible"})

    assert response.status_code == 200
    assert response.json()["db_password"] == "secret_admin_password"
    assert response.json()["headers"]["x-lab-token"] == "visible"


def test_api9_forgotten_inventory_endpoint_exposes_all_orders():
    client.post("/checkout", json={"order_id": "inventory-leak", "user_id": 1})
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
