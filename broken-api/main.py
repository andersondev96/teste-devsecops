import jwt
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional

app = FastAPI(title="Mitigated API", version="1.2")

# ============================================================================
# CONFIGURAÇÕES TÉCNICAS (JWT)
# ============================================================================
SECRET_KEY = "sua_chave_secreta_super_robusta_para_o_tcc"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Mock do banco de dados (ADICIONADO O CAMPO PASSWORD PARA EVITAR KEYERROR)
users_db = {
    1: {"id": 1, "username": "alice", "email": "alice@empresa.com", "is_admin": False, "password": "password123"},
    2: {"id": 2, "username": "bob", "email": "bob@empresa.com", "is_admin": False, "password": "password456"},
    99: {"id": 99, "username": "admin", "email": "admin@empresa.com", "is_admin": True, "password": "admin_password"}
}

class LoginModel(BaseModel):
    username: str
    password: str

# Configuração de Segurança Base para interceptar o token
security = HTTPBearer()

# --- FUNÇÕES AUXILIARES DE JWT ---
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    MITIGAÇÃO API2: Agora valida um token JWT real, verifica a assinatura e a expiração.
    """
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Token inválido")

        for user in users_db.values():
            if user["username"] == username:
                return user
        raise HTTPException(status_code=401, detail="Usuário não encontrado")
    except Exception:
        raise HTTPException(status_code=401, detail="Token expirado ou inválido")

# ============================================================================
# 1. API2:2023 - Broken Authentication -> MITIGADO COM JWT
# ============================================================================
@app.post("/api/v1/login")
def login(login_data: LoginModel):
    # Procura o usuário pelo username
    user = next((u for u in users_db.values() if u["username"] == login_data.username), None)

    # Verifica se o usuário existe e se a senha confere
    if not user or user["password"] != login_data.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")

    # Gera um JWT real com tempo de expiração
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

# ============================================================================
# 2. API1:2023 - Broken Object Level Authorization (BOLA) -> MITIGADO
# ============================================================================
@app.get("/api/v1/users/{user_id}")
def get_user(user_id: int, current_user: dict = Depends(get_current_user)):
    user = users_db.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Validação de Propriedade: Usuário comum só vê a si mesmo
    if current_user["id"] != user_id and not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="BOLA Bloqueado: Acesso negado a dados de terceiros.")

    return user

# ============================================================================
# 3. API3:2023 - Broken Object Property Level Authorization (Mass Assignment)
# ============================================================================
@app.put("/api/v1/users/{user_id}")
async def update_user(user_id: int, request: Request):
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
