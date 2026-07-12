# Mock database
users_db = {
    1: {"id": 1, "username": "alice", "email": "alice@empresa.com", "is_admin": False, "password": "password123"},
    2: {"id": 2, "username": "bob", "email": "bob@empresa.com", "is_admin": False, "password": "password456"},
    99: {"id": 99, "username": "admin", "email": "admin@empresa.com", "is_admin": True, "password": "admin_password"}
}

def get_user_by_username(username: str):
    return next((user for user in users_db.values() if user["username"] == username), None)

def get_user_by_id(user_id: int):
    return users_db.get(user_id)