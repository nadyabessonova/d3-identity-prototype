"""HTTP gateway for invoking D3-protected service agents.

The gateway exposes the existing prototype through FastAPI without rewriting the
protocol modules. It orchestrates the same library calls used by the CLI demo:
store publication, broker discovery, DAP capability creation, EncCAP wrapping,
IDAP authorization, transcript verification, and encrypted A2A payload exchange.
"""

from datetime import datetime, timedelta, timezone
import json
import secrets
import subprocess
from threading import Lock
from time import perf_counter
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

import broker
import config
import dap
from demo import (
    canonical,
    compute_transcript,
    derive_tls_like_key,
    publish_identity,
    publish_registry,
    sign_request,
)
import identity
import idap
import metrics
from services import PROVIDER_ALIASES, PROVIDER_REGISTRY, SERVICE_REGISTRY
from session import EphemeralSession, decrypt_message, encrypt_message


DEFAULT_PAYMENT_CONSTRAINTS = {
    "merchant": {"in": ["Lufthansa", "Air France"]},
    "amount": {"lte": 300},
    "currency": {"eq": "EUR"},
}
PAYMENT_ACTION = "authorize_payment"
PURCHASE_ACTION = "purchase_ticket"


class InvokeRequest(BaseModel):
    provider: str | None = Field(
        default=None,
        description=(
            "Optional provider alias. If omitted, Broker discovery searches all "
            "published providers."
        ),
    )
    action: str
    input_type: str | None = None
    output_type: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    capability_action: str | None = Field(
        default=None,
        description=(
            "Optional negative-test field. Discovery and the IDAP request use "
            "'action', while the signed CAP authority uses this value. If it "
            "differs from 'action', IDAP should reject the request."
        ),
    )
    capability_constraints: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Optional generic constraints inserted into the signed CAP "
            "authority and enforced by IDAP against the request payload."
        ),
    )


def _escape_txt(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _format_txt(fields):
    return "".join(f"{key}={value};" for key, value in fields.items())


def _chunk_string(value, chunk_size=240):
    return [value[index:index + chunk_size] for index in range(0, len(value), chunk_size)]


def _publish_registry_dns_safe(store, provider, service_sids):
    """Publish provider registry while respecting DNS TXT string length limits."""
    if config.STORE_TYPE != "KNOT_DNS":
        publish_registry(store, provider, service_sids)
        return

    value = _format_txt(
        {
            "type": "registry",
            "sid": provider["sid"],
            "services": ",".join(service_sids),
            "ver": "1",
        }
    )
    txt_parts = " ".join(
        f'"{_escape_txt(part)}"' for part in _chunk_string(value)
    )
    name = store._record_name(provider["sid"], "metadata")
    update = (
        f"server {store.server}\n"
        f"zone {store.zone}\n"
        f"update delete {name} TXT\n"
        f"update add {name} {store.ttl} TXT {txt_parts}\n"
        "send\n"
    )
    result = subprocess.run(
        [
            "nsupdate",
            "-y",
            f"hmac-sha256:{store.tsig_key_name}:{store.tsig_secret}",
        ],
        input=update,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"nsupdate failed for {name}: {detail}")


def _constraints_for_request(request):
    if request.capability_constraints is not None:
        return request.capability_constraints
    if request.action == PAYMENT_ACTION:
        return DEFAULT_PAYMENT_CONSTRAINTS
    return None


def _purchase_authorization_from_payload(payload):
    authorization = payload.get("purchase_authorization")
    if not isinstance(authorization, dict):
        return None
    enc_cap = authorization.get("enc_cap")
    if isinstance(enc_cap, dict):
        return enc_cap
    if authorization.get("alg") == "X25519-A256GCM-PoC":
        return authorization
    return None


def _service_for_action(action):
    service = SERVICE_REGISTRY.get(action)
    if service is None:
        raise HTTPException(status_code=404, detail=f"Unknown action: {action}")
    return service


def _resolve_io_types(request):
    service = _service_for_action(request.action)
    return (
        request.input_type or service.input_type,
        request.output_type or service.output_type,
    )


class D3Runtime:
    """Process-local runtime state for the gateway demonstration."""

    def __init__(self):
        self._lock = Lock()
        self._initialized = False
        self.store = None
        self.cp = None
        self.c1 = None
        self.providers = {}
        self.services_by_sid = {}
        self.service_identities_by_action = {}

    def ensure_initialized(self):
        with self._lock:
            if self._initialized:
                return

            config.reset_store()
            idap.reset_runtime_state()
            self.store = metrics.timed(
                "gateway initialize store",
                "gateway_startup",
                "gateway_initialize_store",
                config.get_store,
            )

            self.cp = metrics.timed(
                "gateway generate CP identity",
                "gateway_startup",
                "gateway_generate_identity_cp",
                lambda: identity.generate_identity("cp", mode=config.STORE_TYPE),
            )
            self.c1 = metrics.timed(
                "gateway generate client identity",
                "gateway_startup",
                "gateway_generate_identity_client",
                lambda: identity.generate_identity("n8n-client", mode=config.STORE_TYPE),
            )

            self._publish_initial_state()
            self._initialized = True

    def _publish_initial_state(self):
        for label, ident in [
            ("cp", self.cp),
            ("client", self.c1),
        ]:
            metrics.timed(
                f"gateway publish {label} identity",
                "gateway_publish",
                f"gateway_publish_identity_{label}",
                lambda ident=ident: publish_identity(self.store, ident),
            )

        for alias, provider_config in PROVIDER_REGISTRY.items():
            provider_identity = metrics.timed(
                f"gateway generate {alias} provider identity",
                "gateway_startup",
                f"gateway_generate_identity_provider_{alias}",
                lambda provider_config=provider_config: identity.generate_identity(
                    provider_config["name"],
                    mode=config.STORE_TYPE,
                ),
            )
            self.providers[alias] = provider_identity
            for old_alias, canonical_alias in PROVIDER_ALIASES.items():
                if canonical_alias == alias:
                    self.providers[old_alias] = provider_identity

            metrics.timed(
                f"gateway publish {alias} provider identity",
                "gateway_publish",
                f"gateway_publish_identity_provider_{alias}",
                lambda ident=provider_identity: publish_identity(self.store, ident),
            )

            service_sids = []
            for action in provider_config["services"]:
                service = SERVICE_REGISTRY[action]
                service_identity = metrics.timed(
                    f"gateway generate {action} service identity",
                    "gateway_startup",
                    f"gateway_generate_identity_service_{action}",
                    lambda service=service: identity.generate_identity(
                        service.__class__.__name__,
                        mode=config.STORE_TYPE,
                    ),
                )
                service_sids.append(service_identity["sid"])
                self.services_by_sid[service_identity["sid"]] = {
                    "identity": service_identity,
                    "service": service,
                    "provider_alias": alias,
                    "provider_identity": provider_identity,
                    "provider_name": provider_config["name"],
                }
                self.service_identities_by_action[action] = service_identity

                metrics.timed(
                    f"gateway publish {action} service identity",
                    "gateway_publish",
                    f"gateway_publish_identity_service_{action}",
                    lambda ident=service_identity: publish_identity(self.store, ident),
                )
                metrics.timed(
                    f"gateway publish {action} service metadata",
                    "gateway_publish",
                    f"gateway_publish_service_metadata_{action}",
                    lambda ident=service_identity, service=service: publish_identity(
                        self.store,
                        ident,
                        {
                            "provider": provider_identity["sid"],
                            "role": "service",
                            "action": service.action,
                            "in": service.input_type,
                            "out": service.output_type,
                            "endpoint": service.endpoint,
                        },
                    ),
                )

            metrics.timed(
                f"gateway publish {alias} provider registry",
                "gateway_publish",
                f"gateway_publish_provider_registry_{alias}",
                lambda provider=provider_identity, service_sids=service_sids: (
                    _publish_registry_dns_safe(self.store, provider, service_sids)
                ),
            )

    def _service_entry_for_action(self, action):
        for service_entry in self.services_by_sid.values():
            if service_entry["service"].action == action:
                return service_entry
        raise HTTPException(
            status_code=500,
            detail=f"Gateway runtime has no service registered for {action}",
        )

    def _purchase_constraints(self, payment_payload, authorization_id):
        airline = payment_payload.get("airline") or payment_payload.get("merchant")
        constraints = {
            "authorization_id": {"eq": authorization_id},
        }
        if payment_payload.get("flight") is not None:
            constraints["flight"] = {"eq": payment_payload["flight"]}
        if airline is not None:
            constraints["airline"] = {"eq": airline}
        if payment_payload.get("amount") is not None:
            constraints["amount"] = {"lte": payment_payload["amount"]}
        if payment_payload.get("currency") is not None:
            constraints["currency"] = {"eq": payment_payload["currency"]}
        return constraints

    def _create_purchase_authorization(self, payment_payload, payment_response, issuer_provider):
        ticket_entry = self._service_entry_for_action(PURCHASE_ACTION)
        ticket_identity = ticket_entry["identity"]
        authorization_id = payment_response["authorization_id"]
        expiry = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
        constraints = self._purchase_constraints(payment_payload, authorization_id)

        cap = dap.create_capability(
            sp=issuer_provider["sid"],
            cp=self.cp["sid"],
            c1=self.c1["sid"],
            s1=ticket_identity["sid"],
            action=PURCHASE_ACTION,
            expiry=expiry,
            quota=1,
            nonce=secrets.token_hex(8),
            cp_private_key=self.cp["private_key"],
            sp_private_key=issuer_provider["private_key"],
            constraints=constraints,
        )
        enc_cap = dap.encrypt_capability(
            cap,
            ticket_identity["encryption_public_key"],
        )
        return {
            "type": "D3-EncCAP",
            "target_action": PURCHASE_ACTION,
            "target_service_sid": ticket_identity["sid"],
            "issuer_provider_sid": issuer_provider["sid"],
            "expires_at": expiry,
            "constraints": constraints,
            "enc_cap": enc_cap,
        }

    def invoke(self, request: InvokeRequest):
        self.ensure_initialized()

        input_type, output_type = _resolve_io_types(request)
        provider_filter = None
        if request.provider:
            provider = self.providers.get(request.provider)
            if provider is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"Unknown provider alias: {request.provider}",
                )
            provider_filter = [provider["sid"]]
        else:
            provider_filter = [
                self.providers[alias]["sid"]
                for alias in PROVIDER_REGISTRY
            ]

        flow_start = perf_counter()
        discovered = metrics.timed(
            "gateway broker discovery",
            "gateway_discovery",
            "gateway_broker_discovery",
            lambda: broker.discover(
                request.action,
                input_type,
                output_type,
                store=self.store,
                provider_sids=provider_filter,
            ),
        )
        if not discovered:
            raise HTTPException(status_code=404, detail="No matching service found")

        service_sid = discovered[0]
        service_entry = self.services_by_sid.get(service_sid)
        if service_entry is None:
            raise HTTPException(
                status_code=500,
                detail="Discovered service is not registered in gateway runtime",
            )

        service_identity = service_entry["identity"]
        service = service_entry["service"]
        provider = service_entry["provider_identity"]
        capability_action = request.capability_action or request.action
        constraints = _constraints_for_request(request)
        if request.action == PURCHASE_ACTION:
            enc_cap = _purchase_authorization_from_payload(request.payload)
            if enc_cap is None:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "purchase_ticket requires a delegated D3 capability",
                        "discovery": "succeeded",
                    },
                )
            try:
                cap = metrics.timed(
                    "gateway decrypt delegated purchase capability",
                    "gateway_dap",
                    "gateway_decrypt_delegated_purchase_capability",
                    lambda: dap.decrypt_capability(
                        enc_cap,
                        service_identity["private_key"],
                    ),
                )
            except Exception:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "invalid delegated D3 capability",
                        "discovery": "succeeded",
                    },
                )
            constraints = cap.get("authority", {}).get("constraints")
            capability_action = cap.get("authority", {}).get("action")
        else:
            expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            cap = metrics.timed(
                "gateway DAP create capability",
                "gateway_dap",
                "gateway_dap_create_capability",
                lambda: dap.create_capability(
                    sp=provider["sid"],
                    cp=self.cp["sid"],
                    c1=self.c1["sid"],
                    s1=service_sid,
                    action=capability_action,
                    expiry=expiry,
                    quota=1,
                    nonce=secrets.token_hex(8),
                    cp_private_key=self.cp["private_key"],
                    sp_private_key=provider["private_key"],
                    constraints=constraints,
                ),
            )

            enc_cap = metrics.timed(
                "gateway DAP encrypt EncCAP",
                "gateway_dap",
                "gateway_dap_encrypt_enc_cap",
                lambda: dap.encrypt_capability(
                    cap,
                    service_identity["encryption_public_key"],
                ),
            )

        idap_request = {
            "enc_cap": enc_cap,
            "target_sid": service_sid,
            "requested_action": request.action,
            "request_nonce": secrets.token_hex(8),
            "payload": request.payload,
        }

        client_session = metrics.timed(
            "gateway client session init",
            "gateway_idap",
            "gateway_client_session_init",
            EphemeralSession,
        )
        E_c1 = metrics.timed(
            "gateway client ephemeral public key",
            "gateway_idap",
            "gateway_client_ephemeral_public_key",
            client_session.public_bytes,
        )
        idap_request["client_ephemeral"] = E_c1.hex()

        metrics.timed(
            "gateway client request sign",
            "gateway_idap",
            "gateway_client_request_sign",
            lambda: sign_request(idap_request, self.c1["sid"]),
        )

        request_payload = metrics.timed(
            "gateway canonical request payload",
            "gateway_idap",
            "gateway_canonical_request_payload",
            lambda: canonical(
                {k: v for k, v in idap_request.items() if k != "client_signature"}
            ),
        )

        auth_response = metrics.timed(
            "gateway IDAP authorize",
            "gateway_idap",
            "gateway_idap_authorize",
            lambda: idap.authenticate_and_authorize(
                idap_request,
                service_identity["private_key"],
                self.store,
            ),
        )
        if auth_response.get("status") != "AUTHORIZED":
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "IDAP authorization rejected",
                    "discovery": "succeeded",
                    "requested_action": request.action,
                    "capability_action": capability_action,
                    "constraints": constraints,
                    "reason": "signed capability authority did not authorize request",
                },
            )

        E_s1 = bytes.fromhex(auth_response["service_ephemeral"])
        sig_s1 = bytes.fromhex(auth_response["service_signature"])
        service_public_key = metrics.timed(
            "gateway resolve service public key",
            "gateway_idap",
            "gateway_resolve_service_public_key",
            lambda: self.store.resolve_public_key(service_sid),
        )
        transcript_hash = metrics.timed(
            "gateway compute transcript",
            "gateway_idap",
            "gateway_compute_transcript",
            lambda: compute_transcript(cap, request_payload, E_c1, E_s1),
        )
        metrics.timed(
            "gateway transcript verify",
            "gateway_idap",
            "gateway_transcript_verify",
            lambda: identity.verify_raw(sig_s1, transcript_hash, service_public_key),
        )

        shared_client = metrics.timed(
            "gateway client shared secret derivation",
            "gateway_idap",
            "gateway_client_shared_secret_derivation",
            lambda: client_session.derive_shared_secret(E_s1),
        )
        client_key = metrics.timed(
            "gateway client session key derivation",
            "gateway_idap",
            "gateway_client_session_key_derivation",
            lambda: derive_tls_like_key(shared_client, transcript_hash),
        )
        if client_key.hex() != auth_response["session_key"]:
            raise HTTPException(status_code=403, detail="Session key mismatch")

        service_response = self._execute_service_securely(
            service,
            request.action,
            request.payload,
            client_key,
        )
        if request.action == PAYMENT_ACTION and service_response.get("authorized"):
            service_response["purchase_authorization"] = metrics.timed(
                "gateway create delegated purchase capability",
                "gateway_dap",
                "gateway_create_delegated_purchase_capability",
                lambda: self._create_purchase_authorization(
                    request.payload,
                    service_response,
                    provider,
                ),
            )
        elapsed = perf_counter() - flow_start
        metrics.log_metric("gateway_summary", "gateway_invoke_total", elapsed)

        return {
            "status": "AUTHORIZED",
            "backend": config.STORE_TYPE,
            "requested_provider": request.provider,
            "discovered_provider": {
                "alias": service_entry["provider_alias"],
                "name": service_entry["provider_name"],
                "sid": provider["sid"],
            },
            "service_sid": service_sid,
            "action": request.action,
            "capability_action": capability_action,
            "capability_constraints": constraints,
            "input_type": input_type,
            "output_type": output_type,
            "service_response": service_response,
            "security": {
                "capability_encrypted": True,
                "idap_authorized": True,
                "transcript_verified": True,
                "session_key_match": True,
                "a2a_encrypted": True,
            },
            "duration_ms": elapsed * 1000,
        }

    def _execute_service_securely(self, service, action, payload, session_key):
        message = json.dumps(
            {"action": action, "payload": payload},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        nonce, ciphertext = metrics.timed(
            "gateway encrypt A2A message",
            "gateway_crypto",
            "gateway_encrypt_message",
            lambda: encrypt_message(session_key, message),
        )
        plaintext = metrics.timed(
            "gateway decrypt A2A message",
            "gateway_crypto",
            "gateway_decrypt_message",
            lambda: decrypt_message(session_key, nonce, ciphertext),
        )
        service_request = json.loads(plaintext.decode())
        return service.execute(service_request["payload"])


runtime = D3Runtime()
app = FastAPI(
    title="D3 Gateway",
    description="HTTP orchestration gateway for the D3 identity/delegation prototype.",
    version="0.2.0",
)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/invoke")
def invoke(request: InvokeRequest):
    return runtime.invoke(request)
