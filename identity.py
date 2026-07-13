"""
Identity layer for DAP / IDAP.

- Always generates Ed25519 identities
- In DNS mode: SID = sha256(pubkey)
- In IPFS mode: SID = PeerID derived from pubkey (NOT node PeerID)
- Always supports signing
"""

import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

KEYS = {}

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def derive_sid(public_key):
    """
    Derive DNS-mode SID as SHA256(public_key_bytes) hex.
    Accepts raw bytes, base64 string, or Ed25519PublicKey.
    """
    if isinstance(public_key, Ed25519PublicKey):
        public_key = public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )
    elif isinstance(public_key, str):
        public_key = base64.b64decode(public_key)

    return hashlib.sha256(public_key).hexdigest()

# ------------------------------------------------------------
# PeerID derivation (IPFS-compatible identity multihash)
# ------------------------------------------------------------

def _base58btc_encode(data):
    value = int.from_bytes(data, "big")
    encoded = ""
    while value:
        value, rem = divmod(value, 58)
        encoded = BASE58_ALPHABET[rem] + encoded
    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading_zeroes + (encoded or "1")


def _uvarint(value):
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _protobuf_field_varint(field_number, value):
    return _uvarint((field_number << 3) | 0) + _uvarint(value)


def _protobuf_field_bytes(field_number, value):
    return _uvarint((field_number << 3) | 2) + _uvarint(len(value)) + value


def derive_peer_id(public_key_bytes):
    public_key_proto = (
        _protobuf_field_varint(1, 1)
        + _protobuf_field_bytes(2, public_key_bytes)
    )
    identity_multihash = b"\x00" + _uvarint(len(public_key_proto)) + public_key_proto
    return _base58btc_encode(identity_multihash)


# ------------------------------------------------------------
# Identity generation
# ------------------------------------------------------------

def generate_identity(name, mode=None):
    private_obj = Ed25519PrivateKey.generate()
    public_obj = private_obj.public_key()

    public_bytes = public_obj.public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    private_bytes = private_obj.private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    encryption_public_bytes = x25519.X25519PrivateKey.from_private_bytes(
        private_bytes
    ).public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )

    if mode == "IPFS":
        sid = derive_peer_id(public_bytes)
    else:
        sid = hashlib.sha256(public_bytes).hexdigest()

    ident = {
        "name": name,
        "sid": sid,
        "public_key": base64.b64encode(public_bytes).decode(),
        "private_key": base64.b64encode(private_bytes).decode(),
        "encryption_public_key": base64.b64encode(encryption_public_bytes).decode(),
    }

    KEYS[sid] = ident
    return ident


# ------------------------------------------------------------
# Key resolution helpers
# ------------------------------------------------------------

def _private_key_obj(private_key):
    if isinstance(private_key, Ed25519PrivateKey):
        return private_key

    if isinstance(private_key, dict):
        private_key = private_key["private_key"]

    if private_key in KEYS:
        private_key = KEYS[private_key]["private_key"]

    return Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(private_key)
    )


def _public_key_obj(public_key):
    if isinstance(public_key, Ed25519PublicKey):
        return public_key

    if isinstance(public_key, dict):
        public_key = public_key["public_key"]

    if public_key in KEYS:
        public_key = KEYS[public_key]["public_key"]

    return Ed25519PublicKey.from_public_bytes(
        base64.b64decode(public_key)
    )


# ------------------------------------------------------------
# Signing / Verification
# ------------------------------------------------------------

def sign(data, private_key):
    if isinstance(data, str):
        data = data.encode()

    signature = _private_key_obj(private_key).sign(data)
    return base64.b64encode(signature).decode()


def verify(signature, data, public_key):
    if isinstance(data, str):
        data = data.encode()

    try:
        _public_key_obj(public_key).verify(
            base64.b64decode(signature),
            data,
        )
        return True
    except Exception:
        return False


def verify_raw(signature, message_bytes, public_key):
    _public_key_obj(public_key).verify(signature, message_bytes)
