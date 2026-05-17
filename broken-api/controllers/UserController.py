from fastapi import HTTPException

from users_db import users_db


def public_user(user: dict):
    return {key: value for key, value in user.items() if key != "password"}


class UserController:
    @staticmethod
    def get_user(user_id: int, current_user: dict = None):
        user = users_db.get(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if current_user and current_user["id"] != user_id and not current_user.get("is_admin"):
            raise HTTPException(status_code=403, detail="Acesso negado")

        return public_user(user)

    @staticmethod
    def get_user_email(user_id: int):
        user = users_db.get(user_id)
        if user:
            return {"email": user["email"]}
        raise HTTPException(status_code=404, detail="User not found")

    @staticmethod
    def is_admin(user_id: int):
        user = users_db.get(user_id)
        if user:
            return {"is_admin": user["is_admin"]}
        raise HTTPException(status_code=404, detail="User not found")
