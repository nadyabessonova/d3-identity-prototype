from datetime import datetime, timedelta, timezone
import json
import secrets
import hashlib
import base64

import broker
import config
import dap
import identity
import idap
from ipfs_store import IPFSStore
from session import EphemeralSession, encrypt_message, decrypt_message
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# ==============================
# Helpers
# ==============================

def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def compute_transcript(capability, request_payload, E_c1, E_s1):
    h = hashlib.sha256()
    h.update(canonical(capability))
    h.update(request_payload)
    h.update(E_c1)
    h.update(E_s1)
    return h.digest()


def derive_tls_like_key(shared_secret, transcript_hash):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=transcript_hash,
        info=b"A2A TLS-like session",
    )
    return hkdf.derive(shared_secret)


def publish_identity(store, ident, metadata=None):
    try:
        store.publish_identity(
            ident["sid"],
            ident["public_key"],
            metadata,
            ident["private_key"],
        )
    except TypeError:
        store.publish_identity(ident["sid"], ident["public_key"], metadata)


def publish_registry(store, provider, service_sids):
    metadata = {"services": service_sids}
    try:
        store.publish_identity(
            provider["sid"],
            provider["public_key"],
            metadata,
            provider["private_key"],
        )
    except TypeError:
        services = ",".join(service_sids)
        store.add_txt_record(
            provider["sid"],
            f"type=agent;sid={provider['sid']};services={services};ver=1;",
        )


def sign_request(request, signer_sid):
    unsigned = {k: v for k, v in request.items() if k != "client_signature"}
    request["client_signature"] = identity.sign(
        json.dumps(unsigned, sort_keys=True, separators=(",", ":")),
        signer_sid,
    )
    return request


# ==============================
# Main Scenario
# ==============================

def run_scenario(store_type):
    config.STORE_TYPE = store_type
    config.reset_store()
    idap.reset_runtime_state()

    print(f"\n=== {store_type} STORE ===")

    if store_type == "DNS":
        store = config.get_store()
        cp_store = sp_store = c1_store = s1_store = store
        discovery_store = store
        idap_store = store
    elif store_type == "IPFS":
        cp_store = IPFSStore("http://127.0.0.1:5002")
        sp_store = IPFSStore("http://127.0.0.1:5003")
        c1_store = IPFSStore("http://127.0.0.1:5004")
        s1_store = IPFSStore("http://127.0.0.1:5005")
        discovery_store = c1_store
        idap_store = s1_store
    else:
        raise ValueError(f"Unknown store type: {store_type}")

    # -------------------------
    # Generate identities
    # -------------------------
    cp = identity.generate_identity("cp", mode=store_type)
    sp = identity.generate_identity("sp", mode=store_type)
    c1 = identity.generate_identity("Scan", mode=store_type)
    s1 = identity.generate_identity("Detect", mode=store_type)

    if store_type == "IPFS":
        print("SP SID:", sp["sid"])

    publish_identity(cp_store, cp)
    publish_identity(sp_store, sp)
    publish_identity(c1_store, c1)
    publish_identity(s1_store, s1)

    # -------------------------
    # Publish service metadata
    # -------------------------
    publish_identity(
        s1_store,
        s1,
        {
            "provider": sp["sid"],
            "role": "service",
            "action": "detect",
            "in": "scan_request",
            "out": "report",
            "endpoint": "local://detect",
        },
    )

    publish_registry(sp_store, sp, [s1["sid"]])

    discovered = broker.discover(
        "detect",
        "scan_request",
        "report",
        store=discovery_store,
        provider_sids=[sp["sid"]],
    )
    detect_sid = discovered[0]

    print("Discovered SID:")
    print(detect_sid)

    # -------------------------
    # Create DAP capability
    # -------------------------
    expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    cap = dap.create_capability(
        sp=sp["sid"],
        cp=cp["sid"],
        c1=c1["sid"],
        s1=detect_sid,
        action="detect",
        expiry=expiry,
        quota=5,
        nonce=secrets.token_hex(8),
        cp_private_key=cp["private_key"],
        sp_private_key=sp["private_key"],
    )

    print("\nCapability JSON:")
    print(json.dumps(cap, indent=2, sort_keys=True))

    enc_cap = dap.encrypt_capability(cap, s1["encryption_public_key"])

    print("\nEncCAP JSON:")
    print(json.dumps(enc_cap, indent=2, sort_keys=True))

    # -------------------------
    # Prepare request
    # -------------------------
    request = {
        "enc_cap": enc_cap,
        "target_sid": detect_sid,
        "requested_action": "detect",
        "request_nonce": secrets.token_hex(8),
        "payload": {"sample": "file-123"},
    }

    client_session = EphemeralSession()
    E_c1 = client_session.public_bytes()
    request["client_ephemeral"] = E_c1.hex()

    sign_request(request, c1["sid"])

    request_payload = canonical(
        {k: v for k, v in request.items() if k != "client_signature"}
    )

    # -------------------------
    # Call IDAP
    # -------------------------
    print("\nValidation result:")
    response = idap.authenticate_and_authorize(
        request, s1["private_key"], idap_store
    )

    print(response["status"])

    if response["status"] != "AUTHORIZED":
        return

    print("\nReplay result:")
    replay = idap.authenticate_and_authorize(
        request, s1["private_key"], idap_store
    )
    print(replay["status"])

    # -------------------------
    # Verify transcript signature
    # -------------------------
    E_s1 = bytes.fromhex(response["service_ephemeral"])
    sig_s1 = bytes.fromhex(response["service_signature"])

    service_public_key = idap_store.resolve_public_key(detect_sid)

    transcript_hash = compute_transcript(
        cap,
        request_payload,
        E_c1,
        E_s1,
    )

    identity.verify_raw(sig_s1, transcript_hash, service_public_key)

    print("Transcript signature verified.")

    # -------------------------
    # Derive shared session key
    # -------------------------
    shared_client = client_session.derive_shared_secret(E_s1)

    client_key = derive_tls_like_key(shared_client, transcript_hash)

    print("Client session key:", client_key.hex())
    print("Server session key:", response["session_key"])
    print("Match:", client_key.hex() == response["session_key"])

    # -------------------------
    # Secure A2A communication
    # -------------------------
    print("\n--- Secure A2A Communication ---")

    message = b'{"action":"detect","payload":"scan_data"}'

    nonce, ciphertext = encrypt_message(client_key, message)
    print("Encrypted:", ciphertext.hex())

    decrypted = decrypt_message(client_key, nonce, ciphertext)
    print("Decrypted:", decrypted.decode())

    # -------------------------
    # Tampering test
    # -------------------------
    tampered_request = json.loads(json.dumps(request))
    tampered_request["requested_action"] = "monitor"
    tampered_request["request_nonce"] = secrets.token_hex(8)
    tampered_request.pop("client_signature", None)
    sign_request(tampered_request, c1["sid"])

    print("\nTampering result:")
    tampered = idap.authenticate_and_authorize(
        tampered_request, s1["private_key"], idap_store
    )

    print(tampered["status"])


def main():
    run_scenario("DNS")
##    run_scenario("IPFS")


if __name__ == "__main__":
    main()
