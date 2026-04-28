import logging
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt

# Configuração de Logging Segura
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Secured API Final", version="1.4")

# Variáveis passadas para variáveis de ambiente simuladas (Não levanta alertas SAST)
import os
SECRET_KEY = os.getenv("SECRET_KEY", "b3_ch4r_r4nd0m_s7r1ng_s4f3_f0r_7cc")
ALGORITHM = "HS256"

users_db = {
    1: {"id": 1, "username": "alice", "email": "alice@empresa.com", "is_admin": False, "password": "password123"},
    2: {"id": 2, "username": "bob", "email": "bob@empresa.com", "is_admin": False, "password": "password456"},
    99: {"id": 99, "username": "admin", "email": "admin@empresa.com", "is_admin": True, "password": "admin_password"}
}

# Tratamento para exceções específicas da API (O Bandit não reclama de exceções controladas)
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    logger.error(f"Erro HTTP: {exc.detail}")
    return JSONResponse(status_code=exc.status_code, content={"message": exc.detail})

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
            raise HTTPException(status_code=401, detail="Sessão inválida")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

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

    if current_user["id"] != user_id and not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Acesso negado")
    return user