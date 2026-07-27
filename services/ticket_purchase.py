"""Deterministic mock ticket purchase service."""


class TicketPurchaseService:
    action = "purchase_ticket"
    input_type = "ticket_purchase_request"
    output_type = "ticket_confirmation"
    endpoint = "local://ticket"

    def execute(self, payload):
        return {
            "ticket": "ETKT-123456789",
            "status": "confirmed",
            "flight": payload.get("flight"),
            "airline": payload.get("airline"),
            "amount": payload.get("amount"),
            "currency": payload.get("currency"),
            "authorization_id": payload.get("authorization_id"),
        }
