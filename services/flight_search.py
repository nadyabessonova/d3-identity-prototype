"""Deterministic mock flight search service."""


class FlightSearchService:
    action = "search_flights"
    input_type = "flight_search_request"
    output_type = "flight_offer"
    endpoint = "local://flight"

    def execute(self, payload):
        airlines = payload.get("airlines") or []
        max_price = payload.get("max_price")

        offers = [
            {
                "flight": "LH241",
                "airline": "Lufthansa",
                "price": 248,
                "currency": "EUR",
            },
            {
                "flight": "AF1177",
                "airline": "Air France",
                "price": 240,
                "currency": "EUR",
            },
        ]

        for offer in offers:
            if airlines and offer["airline"] not in airlines:
                continue
            if max_price is not None and offer["price"] > max_price:
                continue
            return offer

        return {
            "flight": None,
            "airline": None,
            "price": None,
            "currency": "EUR",
            "status": "no_offer",
        }
