from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import base64
import sqlite3

app = FastAPI(title="Mitigated API", version="1.1")

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

# Configuração de Segurança Base para interceptar o token
security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Função para extrair o usuário da requisição atual.
    Nota: A decodificação Base64 ainda é vulnerável (API2), mas é necessária
    agora para podermos identificar o usuário e mitigar o BOLA (API1).
    """
    try:
        username = base64.b64decode(credentials.credentials).decode()
        for user in users_db.values():
            if user["username"] == username:
                return user
        raise HTTPException(status_code=401, detail="Usuário não encontrado no sistema.")
    except Exception:
        raise HTTPException(status_code=401, detail="Token inválido ou ausente.")


# ============================================================================
# 1. API2:2023 - Broken Authentication (Será mitigado no próximo passo)
# ============================================================================
@app.post("/api/v1/login")
def login(login_data: LoginModel):
    # FALHA AINDA ATIVA: O "token" é apenas o username em Base64.
    fake_token = base64.b64encode(login_data.username.encode()).decode()
    return {"access_token": fake_token, "type": "bearer"}


# ============================================================================
# 2. API1:2023 - Broken Object Level Authorization (BOLA) -> MITIGADO
# ============================================================================
@app.get("/api/v1/users/{user_id}")
def get_user(user_id: int, current_user: dict = Depends(get_current_user)):
    user = users_db.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # MITIGAÇÃO BOLA: Validação Rigorosa de Propriedade (Ownership)
    # Bloqueia a requisição se o usuário tentar ver um ID que não é dele
    # (a menos que seja um administrador).
    if current_user["id"] != user_id and not current_user.get("is_admin"):
        raise HTTPException(
            status_code=403,
            detail="BOLA Bloqueado: Você não tem autorização para aceder aos dados deste utilizador."
        )

    return user


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
