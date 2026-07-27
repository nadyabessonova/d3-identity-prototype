"""Mock payment authorization service.

Authorization constraints are enforced by IDAP before this service is called.
"""


class PaymentAuthorizationService:
    action = "authorize_payment"
    input_type = "payment_request"
    output_type = "payment_authorization"
    endpoint = "local://payment"

    def execute(self, payload):
        return {
            "authorized": True,
            "authorization_id": "AUTH-123456",
            "merchant": payload.get("merchant"),
            "flight": payload.get("flight"),
            "airline": payload.get("airline") or payload.get("merchant"),
            "amount": payload.get("amount"),
            "currency": payload.get("currency"),
        }
