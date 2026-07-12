from pydantic import BaseModel, ConfigDict

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginModel(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "username": "alice",
                "password": "password123",
            }
        }
    )
    username: str
    password: str