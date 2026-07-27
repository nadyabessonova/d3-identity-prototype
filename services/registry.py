"""Service registry for D3-protected local mock agents."""

from .detect import DetectService
from .flight_search import FlightSearchService
from .notification import NotificationService
from .payment_authorization import PaymentAuthorizationService
from .ticket_purchase import TicketPurchaseService


SERVICE_REGISTRY = {
    "detect": DetectService(),
    "search_flights": FlightSearchService(),
    "authorize_payment": PaymentAuthorizationService(),
    "purchase_ticket": TicketPurchaseService(),
    "send_notification": NotificationService(),
}
