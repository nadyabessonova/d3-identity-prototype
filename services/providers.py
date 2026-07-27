"""Provider layout for the federated Travel Assistant gateway scenario."""


PROVIDER_REGISTRY = {
    "security": {
        "name": "SecurityProvider",
        "services": ["detect"],
    },
    "travel": {
        "name": "TravelProvider",
        "services": ["search_flights", "purchase_ticket"],
    },
    "payment": {
        "name": "PaymentProvider",
        "services": ["authorize_payment"],
    },
    "notification": {
        "name": "NotificationProvider",
        "services": ["send_notification"],
    },
}

# Backward-compatible alias for older gateway examples.
PROVIDER_ALIASES = {
    "sp": "security",
}
