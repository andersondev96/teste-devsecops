import os
import json
import urllib.request
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from controllers.UserController import UserController
from controllers.ProductController import ProductController
from controllers.CheckoutController import CheckoutController
from ..routes.UserRoutes import router
from users_db import users_db

app = FastAPI(title="Broken API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    ProductController.initialize_database()

app.include_router(router)

@app.get("/api/v1/users/{user_id}/email")
def get_user_email(user_id: int):
    return UserController.get_user_email(user_id)

@app.get("/api/v1/products")
def get_products():
    return ProductController.get_products()

@app.get("/api/v1/users/{user_id}/is_admin")
def is_admin(user_id: int):
    return UserController.is_admin(user_id)

@app.post("/api/v1/checkout/complete")
async def complete_checkout(request: Request):
    return await CheckoutController.complete_checkout(request)

@app.get("/api/v1/proxy")
def proxy_request(url: str):
    # API7:2023 - Server Side Request Forgery (SSRF)
    with urllib.request.urlopen(url) as response:
        return response.read().decode('utf-8')

@app.get("/api/v1/debug")
def get_debug_info():
    # API8:2023 - Security Misconfiguration
    return dict(os.environ)

@app.get("/api/v0/users")
def get_all_users_deprecated():
    # API9:2023 - Improper Inventory Management
    return users_db

@app.post("/api/v1/process_external")
def process_external_data(api_url: str):
    # API10:2023 - Unsafe Consumption of APIs
    try:
        with urllib.request.urlopen(api_url) as response:
            data = json.loads(response.read().decode('utf-8'))
            return {"status": "success", "processed_data": data}
    except Exception as e:
        return {"error": str(e)}
