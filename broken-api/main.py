from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import base64
import sqlite3

app = FastAPI(title="Vunerable API", version="1.0")

# ============================================================================
# VULNERABILIDADE EXTRA: Secret Hardcoded (Será pego no Secret Scanning)
# ============================================================================
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "super_secret_admin_password_123"

# Mock do banco de dados em memória para agilizar o MVP
users_db = {
    1: {"id": 1, "username": "alice", "email": "alice@empresa.com", "is_admin": False},
    2: {"id": 2, "username": "bob", "email": "bob@empresa.com", "is_admin": False},
    99: {"id": 99, "username": "admin", "email": "admin@empresa.com", "is_admin": True}
}

class LoginModel(BaseModel):
    username: str
    password: str

# ============================================================================
# 1. API1:2023 - Broken Access Control
# ============================================================================
@app.post("/api/v1/login")
def login(login_data: LoginModel):
    # FALHA: Não há rate limiting (permite brute force).
    # FALHA: O "token" é apenas o username em Base64, super fácil de forjar.
    fake_token = base64.b64encode(login_data.username.encode()).decode()
    return {"access_token": fake_token, "type": "bearer"}

# ============================================================================
# 2. API2:2023 - Broken Object Level Authorization (BOLA)
# ===========================================================================
@app.get("/api/v1/users/{user_id}")
def get_user(user_id: int):
    # FALHA: A API não verifica de quem é o token de acesso.
    # Qualquer usuário autenticado (ou até sem autenticação, nesse caso)
    # Pode alterar o ID na URL e ver os dados de outros usuários (ex: admin 99).
    user = users_db.get(user_id)
    if user:
        return user
    raise HTTPException(status_code=404, detail="User not found")

# ============================================================================
# 3. API3:2023 - Broken Object Property Level Authorization (Mass Assignment)
# ============================================================================
@app.put("/api/v1/users/{user_id}")
async def update_user(user_id: int, request: Request):
    # FALHA: A API aceita um JSON genérico e injeta diretamente no banco.
    # Um atacante pode enviar {"is_admin": true} para se promover a admin.
    body = await request.json()
    if user_id in users_db:
        users_db[user_id].update(body)
        return users_db[user_id]
    raise HTTPException(status_code=404, detail="User not found")

# ============================================================================
# 4. API4:2023 - Unrestricted Resource Consumption
# ============================================================================

# ============================================================================
# 5. API5:2023 - Broken Function Level Authorization
# ============================================================================

# ============================================================================
# 6. API6:2023 - Unrestricted Access to Sensitive Business Flows
# ============================================================================

# ============================================================================
# 7. API7:2023 - Server Side Request Forgery
# ============================================================================

# ============================================================================
# 8. API8:2023 - Security Misconfiguration
# ============================================================================

# ============================================================================
# 9. API9:2023 - Improper Inventory Management
# ============================================================================

# ============================================================================
# 10. API10:2023 - Unsafe Consumption of APIs
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
