from fastapi import Request

class CheckoutController:
    @staticmethod
    async def complete_checkout(request: Request):
        # API6:2023 - Unrestricted Access to Sensitive Business Flows
        data = await request.json()
        order_id = data.get('order_id')
        return {"status": "success", "order": order_id}
