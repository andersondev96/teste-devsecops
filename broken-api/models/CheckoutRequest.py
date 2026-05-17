from pydantic import BaseModel

class CheckoutRequest(BaseModel):
    order_id: str
