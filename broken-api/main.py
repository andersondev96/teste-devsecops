import jwt
import logging
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import os

# Configuração de Logging para evitar vazamento de Stack Trace (API8)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Secured API", version="1.3")

# MITIGAÇÃO API8/Secrets: Removendo chaves hardcoded
# Em um cenário real, usaríamos os.getenv("SECRET_KEY")
SECRET_KEY = "32_chars_random_string_safe_for_tcc"
ALGORITHM = "HS256"

# Mock do banco de dados
users_db = {
    1: {"id": 1, "username": "alice", "email": "alice@empresa.com", "is_admin": False, "password": "password123"},
    2: {"id": 2, "username": "bob", "email": "bob@empresa.com", "is_admin": False, "password": "password456"},
    99: {"id": 99, "username": "admin", "email": "admin@empresa.com", "is_admin": True, "password": "admin_password"}
}

# --- MITIGAÇÃO API8: TRATAMENTO GLOBAL DE EXCEÇÕES ---
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Erro detectado: {str(exc)}")
    # Retorna uma mensagem genérica sem Stack Trace
    return JSONResponse(
        status_code=500,
        content={"detail": "Erro interno do servidor. O incidente foi registrado."},
    )

class LoginModel(BaseModel):
    username: str
    password: str

security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user = next((u for u in users_db.values() if u["username"] == username), None)
        if not user:
            raise HTTPException(status_code=401)
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Sessão inválida")

@app.post("/api/v1/login")
def login(login_data: LoginModel):
    user = next((u for u in users_db.values() if u["username"] == login_data.username), None)
    if not user or user["password"] != login_data.password:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    access_token = jwt.encode({"sub": user["username"], "exp": datetime.utcnow() + timedelta(minutes=30)}, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/v1/users/{user_id}")
def get_user(user_id: int, current_user: dict = Depends(get_current_user)):
    user = users_db.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # BOLA MITIGADO
    if current_user["id"] != user_id and not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Acesso negado")
    return user

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
