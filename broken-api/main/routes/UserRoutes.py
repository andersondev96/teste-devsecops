from fastapi import APIRouter, Depends
from controllers.UserController import UserController
from controllers.AuthController import AuthController
from models.LoginModel import LoginModel

router = APIRouter(prefix="/api/v1")

@router.post("/login")
def login(login_data: LoginModel):
    return AuthController.login(login_data)

@router.get("/users/{user_id}")
def get_user(user_id: int, current_user: dict = Depends(AuthController.get_current_user)):
    return UserController.get_user(user_id, current_user)