from fastapi import APIRouter, Depends, HTTPException
from main.server.base import get_user_by_id
from main.server.user import User
from main.server.auth import get_current_user

router = APIRouter()

@router.get("/users/{user_id}", response_model=User)
def get_user(user_id: int, current_user: dict = Depends(get_current_user)):
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if current_user["id"] != user_id and not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Acesso negado")

    return User(**user)