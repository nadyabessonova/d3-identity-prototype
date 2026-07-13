"""DAP: create, verify, and wrap the signed Delegation Artifact as EncCAP."""

import base64
import json
import os

import identity
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


SIGNED_FIELDS = ("sp", "cp", "c1", "s1", "authority", "control")


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _derive_enc_key(shared_secret, recipient_sid, ephemeral_public):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=recipient_sid.encode(),
        info=b"D3 EncCAP PoC" + ephemeral_public,
    )
    return hkdf.derive(shared_secret)


def canonicalize_cap_payload(cap):
    """Return canonical JSON for fields covered by cp/sp signatures."""
    payload = {field: cap[field] for field in SIGNED_FIELDS}
    return _canonical(payload)


def create_capability(
    sp,
    cp,
    c1,
    s1,
    action,
    expiry,
    quota,
    nonce,
    cp_private_key,
    sp_private_key,
):
    """Create a DAP capability signed by cp and sp.

    DAP does not resolve SIDs or enforce policy; it only shapes and signs
    the artifact.
    """
    cap = {
        "sp": sp,
        "cp": cp,
        "c1": c1,
        "s1": s1,
        "authority": {"action": action},
        "control": {
            "expiry": expiry,
            "quota": quota,
            "nonce": nonce,
        },
    }
    payload = canonicalize_cap_payload(cap)
    cap["sig_cp"] = identity.sign(payload, cp_private_key)
    cap["sig_sp"] = identity.sign(payload, sp_private_key)
    return cap


def verify_capability_signatures(cap, cp_public_key, sp_public_key):
    """Verify the two DAP signatures using caller-supplied public keys."""
    try:
        payload = canonicalize_cap_payload(cap)
    except KeyError:
        return False

    return (
        identity.verify(cap.get("sig_cp", ""), payload, cp_public_key)
        and identity.verify(cap.get("sig_sp", ""), payload, sp_public_key)
    )


def encrypt_capability(cap, service_encryption_public_key):
    """Return EncCAP, the service-agent encrypted signed capability.

    The paper defines EncCAP as CAP encrypted to P_sa. This PoC keeps the CAP
    schema unchanged and wraps its canonical JSON in an X25519/AES-GCM envelope.
    """
    recipient_public = x25519.X25519PublicKey.from_public_bytes(
        base64.b64decode(service_encryption_public_key)
    )
    ephemeral = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    shared_secret = ephemeral.exchange(recipient_public)
    key = _derive_enc_key(shared_secret, cap["s1"], ephemeral_public)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, _canonical(cap).encode(), None)
    return {
        "alg": "X25519-A256GCM-PoC",
        "recipient": cap["s1"],
        "ephemeral_public": base64.b64encode(ephemeral_public).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def decrypt_capability(enc_cap, service_private_key):
    """Decrypt an EncCAP envelope using the service agent private key."""
    private_bytes = base64.b64decode(service_private_key)
    service_encryption_private = x25519.X25519PrivateKey.from_private_bytes(
        private_bytes
    )
    ephemeral_public = base64.b64decode(enc_cap["ephemeral_public"])
    shared_secret = service_encryption_private.exchange(
        x25519.X25519PublicKey.from_public_bytes(ephemeral_public)
    )
    key = _derive_enc_key(shared_secret, enc_cap["recipient"], ephemeral_public)
    plaintext = AESGCM(key).decrypt(
        base64.b64decode(enc_cap["nonce"]),
        base64.b64decode(enc_cap["ciphertext"]),
        None,
    )
    return json.loads(plaintext.decode())
