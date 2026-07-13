"""IDAP: TLS-inspired runtime authentication and authorization."""

from datetime import datetime, timezone
import json
import hashlib
import base64

import config
import dap
import identity


_SEEN_PRESENTATIONS = set()
_CAPABILITY_USE_COUNT = {}


def reset_runtime_state():
    """Clear IDAP replay/quota state for isolated demo or test runs."""
    _SEEN_PRESENTATIONS.clear()
    _CAPABILITY_USE_COUNT.clear()


# ==============================
# Helpers
# ==============================

def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _unsigned_request(request):
    return {k: v for k, v in request.items() if k != "client_signature"}


def _expiry_passed(expiry):
    try:
        expires_at = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
    except Exception:
        return True
    return datetime.now(timezone.utc) > expires_at


def _quota_available(quota):
    return isinstance(quota, int) and quota > 0


def _capability_from_request(request, service_private_key):
    if "enc_cap" in request:
        if service_private_key is None:
            raise ValueError("service_private_key required for EncCAP")
        return dap.decrypt_capability(request["enc_cap"], service_private_key)
    return request.get("capability", {})


def _capability_id(cap):
    return cap.get("control", {}).get("nonce") or hashlib.sha256(
        _canonical(cap)
    ).hexdigest()


def _presentation_id(cap, request):
    request_nonce = request.get("request_nonce")
    if request_nonce is None:
        request_nonce = request.get("client_signature", "")
    return f"{_capability_id(cap)}:{request_nonce}"


def _usage_available(cap):
    quota = cap.get("control", {}).get("quota")
    cap_id = _capability_id(cap)
    return _quota_available(quota) and _CAPABILITY_USE_COUNT.get(cap_id, 0) < quota


def _sequence_matches(cap, request):
    expected = cap.get("control", {}).get("sequence")
    return expected is None or request.get("sequence") == expected


def _mark_presentation_used(cap, request):
    cap_id = _capability_id(cap)
    _SEEN_PRESENTATIONS.add(_presentation_id(cap, request))
    _CAPABILITY_USE_COUNT[cap_id] = _CAPABILITY_USE_COUNT.get(cap_id, 0) + 1


def _compute_transcript(capability, request_payload, E_c1_bytes, E_s1_bytes):
    """
    TLS-like transcript binding:
    H(capability || request || E_c1 || E_s1)
    """
    h = hashlib.sha256()
    h.update(_canonical(capability))
    h.update(request_payload)
    h.update(E_c1_bytes)
    h.update(E_s1_bytes)
    return h.digest()


def _derive_tls_like_key(shared_secret, transcript_hash):
    """
    HKDF-based key derivation (TLS-like).
    """
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=transcript_hash,
        info=b"A2A TLS-like session",
    )
    return hkdf.derive(shared_secret)


# ==============================
# Main IDAP Entry Point
# ==============================

def authenticate_and_authorize(request, service_private_key=None, store=None):
    """
    Validate runtime request against DAP capability
    and perform TLS-like authenticated ephemeral DH.
    """

    store = store or config.get_store()
    try:
        cap = _capability_from_request(request, service_private_key)
    except Exception:
        return {"status": "REJECTED"}

    client_sid = cap.get("c1")
    target_sid = request.get("target_sid")
    requested_action = request.get("requested_action")

    # ==============================
    # Resolve identities
    # ==============================

    cp_key = store.resolve_public_key(cap.get("cp"))
    sp_key = store.resolve_public_key(cap.get("sp"))
    c1_key = store.resolve_public_key(client_sid)
    s1_key = store.resolve_public_key(cap.get("s1"))

    if not all([cp_key, sp_key, c1_key, s1_key]):
        return {"status": "REJECTED"}

    # ==============================
    # Verify DAP signatures
    # ==============================

    if not dap.verify_capability_signatures(cap, cp_key, sp_key):
        return {"status": "REJECTED"}

    # ==============================
    # Verify client request signature
    # ==============================

    request_payload = _canonical(_unsigned_request(request))

    if not identity.verify(
        request.get("client_signature", ""),
        request_payload.decode(),
        c1_key,
    ):
        return {"status": "REJECTED"}

    # ==============================
    # Enforce policy constraints
    # ==============================

    if cap.get("s1") != target_sid:
        return {"status": "REJECTED"}

    if cap.get("authority", {}).get("action") != requested_action:
        return {"status": "REJECTED"}

    if not _sequence_matches(cap, request):
        return {"status": "REJECTED"}

    if _expiry_passed(cap.get("control", {}).get("expiry", "")):
        return {"status": "REJECTED"}

    if _presentation_id(cap, request) in _SEEN_PRESENTATIONS:
        return {"status": "REJECTED"}

    if not _usage_available(cap):
        return {"status": "REJECTED"}

    # If no handshake required
    if service_private_key is None:
        _mark_presentation_used(cap, request)
        return {"status": "AUTHORIZED"}

    # ==============================
    # TLS-LIKE HANDSHAKE
    # ==============================

    from session import EphemeralSession

    client_ephemeral_hex = request.get("client_ephemeral")
    if not client_ephemeral_hex:
        return {"status": "REJECTED"}

    E_c1_bytes = bytes.fromhex(client_ephemeral_hex)

    # Generate server ephemeral
    service_session = EphemeralSession()
    E_s1_bytes = service_session.public_bytes()

    # Compute transcript hash
    transcript_hash = _compute_transcript(
        cap,
        request_payload,
        E_c1_bytes,
        E_s1_bytes,
    )

    # Sign transcript (NOT just E_s1)
    sig_s1_b64 = identity.sign(transcript_hash, service_private_key)
    sig_s1_bytes = base64.b64decode(sig_s1_b64)

    # Compute shared secret
    shared_secret = service_session.derive_shared_secret(E_c1_bytes)

    # TLS-like key derivation
    session_key = _derive_tls_like_key(shared_secret, transcript_hash)
    _mark_presentation_used(cap, request)

    return {
        "status": "AUTHORIZED",
        "service_ephemeral": E_s1_bytes.hex(),
        "service_signature": sig_s1_bytes.hex(),
        "session_key": session_key.hex(),
    }
