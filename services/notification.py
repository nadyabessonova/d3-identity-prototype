"""Deterministic mock notification service."""


class NotificationService:
    action = "send_notification"
    input_type = "notification_request"
    output_type = "notification_status"
    endpoint = "local://notify"

    def execute(self, payload):
        return {
            "status": "sent",
            "recipient": payload.get("recipient"),
        }
