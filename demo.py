from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets
from time import perf_counter

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import broker
import config
import dap
import identity
import idap
import metrics
from session import EphemeralSession, decrypt_message, encrypt_message


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


def main():
    flow_start = perf_counter()

    config.reset_store()
    idap.reset_runtime_state()

    store = metrics.timed(
        "initialize store",
        "startup",
        "initialize_store",
        config.get_store,
    )

    cp = metrics.timed(
        "generate CP identity",
        "startup",
        "generate_identity_cp",
        lambda: identity.generate_identity("cp", mode=config.STORE_TYPE),
    )
    sp = metrics.timed(
        "generate SP identity",
        "startup",
        "generate_identity_sp",
        lambda: identity.generate_identity("sp", mode=config.STORE_TYPE),
    )
    c1 = metrics.timed(
        "generate C1 identity",
        "startup",
        "generate_identity_c1",
        lambda: identity.generate_identity("Scan", mode=config.STORE_TYPE),
    )
    s1 = metrics.timed(
        "generate S1 identity",
        "startup",
        "generate_identity_s1",
        lambda: identity.generate_identity("Detect", mode=config.STORE_TYPE),
    )

    metrics.timed(
        "publish CP identity",
        "publish",
        "publish_identity_cp",
        lambda: publish_identity(store, cp),
    )
    metrics.timed(
        "publish SP identity",
        "publish",
        "publish_identity_sp",
        lambda: publish_identity(store, sp),
    )
    metrics.timed(
        "publish C1 identity",
        "publish",
        "publish_identity_c1",
        lambda: publish_identity(store, c1),
    )
    metrics.timed(
        "publish S1 identity",
        "publish",
        "publish_identity_s1",
        lambda: publish_identity(store, s1),
    )

    metrics.timed(
        "publish service metadata",
        "publish",
        "publish_service_metadata",
        lambda: publish_identity(
            store,
            s1,
            {
                "provider": sp["sid"],
                "role": "service",
                "action": "detect",
                "in": "scan_request",
                "out": "report",
                "endpoint": "local://detect",
            },
        ),
    )

    metrics.timed(
        "publish provider registry",
        "publish",
        "publish_provider_registry",
        lambda: publish_registry(store, sp, [s1["sid"]]),
    )

    discovered = metrics.timed(
        "broker discovery",
        "discovery",
        "broker_discovery",
        lambda: broker.discover(
            "detect",
            "scan_request",
            "report",
            store=store,
            provider_sids=[sp["sid"]],
        ),
    )
    detect_sid = discovered[0]

    print("Discovered SID:")
    print(detect_sid)

    expiry = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    cap = metrics.timed(
        "DAP create capability",
        "dap",
        "dap_create_capability",
        lambda: dap.create_capability(
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
        ),
    )

    print("\nCapability JSON:")
    print(json.dumps(cap, indent=2, sort_keys=True))

    enc_cap = metrics.timed(
        "DAP encrypt EncCAP",
        "dap",
        "dap_encrypt_enc_cap",
        lambda: dap.encrypt_capability(cap, s1["encryption_public_key"]),
    )

    print("\nEncCAP JSON:")
    print(json.dumps(enc_cap, indent=2, sort_keys=True))

    request = {
        "enc_cap": enc_cap,
        "target_sid": detect_sid,
        "requested_action": "detect",
        "request_nonce": secrets.token_hex(8),
        "payload": {"sample": "file-123"},
    }

    client_session = metrics.timed(
        "client session init",
        "idap",
        "client_session_init",
        EphemeralSession,
    )
    E_c1 = metrics.timed(
        "client ephemeral public key",
        "idap",
        "client_ephemeral_public_key",
        client_session.public_bytes,
    )
    request["client_ephemeral"] = E_c1.hex()

    metrics.timed(
        "client request sign",
        "idap",
        "client_request_sign",
        lambda: sign_request(request, c1["sid"]),
    )

    request_payload = metrics.timed(
        "canonical request payload",
        "idap",
        "canonical_request_payload",
        lambda: canonical(
            {k: v for k, v in request.items() if k != "client_signature"}
        ),
    )

    print("\nValidation result:")
    response = metrics.timed(
        "IDAP authorize",
        "idap",
        "idap_authorize",
        lambda: idap.authenticate_and_authorize(
            request,
            s1["private_key"],
            store,
        ),
    )

    print(response["status"])

    if response["status"] != "AUTHORIZED":
        return

    print("\nReplay result:")
    replay = metrics.timed(
        "IDAP replay check",
        "idap",
        "idap_replay_check",
        lambda: idap.authenticate_and_authorize(
            request,
            s1["private_key"],
            store,
        ),
    )
    print(replay["status"])

    E_s1 = bytes.fromhex(response["service_ephemeral"])
    sig_s1 = bytes.fromhex(response["service_signature"])

    service_public_key = metrics.timed(
        "resolve service public key",
        "idap",
        "resolve_service_public_key",
        lambda: store.resolve_public_key(detect_sid),
    )

    transcript_hash = metrics.timed(
        "compute transcript",
        "idap",
        "compute_transcript",
        lambda: compute_transcript(
            cap,
            request_payload,
            E_c1,
            E_s1,
        ),
    )

    metrics.timed(
        "transcript verify",
        "idap",
        "transcript_verify",
        lambda: identity.verify_raw(sig_s1, transcript_hash, service_public_key),
    )

    print("Transcript signature verified.")

    shared_client = metrics.timed(
        "client shared secret derivation",
        "idap",
        "client_shared_secret_derivation",
        lambda: client_session.derive_shared_secret(E_s1),
    )

    client_key = metrics.timed(
        "client session key derivation",
        "idap",
        "client_session_key_derivation",
        lambda: derive_tls_like_key(shared_client, transcript_hash),
    )

    print("Client session key:", client_key.hex())
    print("Server session key:", response["session_key"])
    print("Match:", client_key.hex() == response["session_key"])

    print("\n--- Secure A2A Communication ---")

    message = b'{"action":"detect","payload":"scan_data"}'

    nonce, ciphertext = metrics.timed(
        "encrypt message",
        "crypto",
        "encrypt_message",
        lambda: encrypt_message(client_key, message),
    )
    print("Encrypted:", ciphertext.hex())

    decrypted = metrics.timed(
        "decrypt message",
        "crypto",
        "decrypt_message",
        lambda: decrypt_message(client_key, nonce, ciphertext),
    )
    print("Decrypted:", decrypted.decode())

    tampered_request = json.loads(json.dumps(request))
    tampered_request["requested_action"] = "monitor"
    tampered_request["request_nonce"] = secrets.token_hex(8)
    tampered_request.pop("client_signature", None)
    metrics.timed(
        "tampered request sign",
        "tampering",
        "tampered_request_sign",
        lambda: sign_request(tampered_request, c1["sid"]),
    )

    print("\nTampering result:")
    tampered = metrics.timed(
        "tampering check",
        "tampering",
        "tampering_check",
        lambda: idap.authenticate_and_authorize(
            tampered_request,
            s1["private_key"],
            store,
        ),
    )

    print(tampered["status"])

    total_elapsed = perf_counter() - flow_start
    print(f"[total] full demo flow: {total_elapsed:.3f}s")
    metrics.log_metric("summary", "total_flow", total_elapsed)


if __name__ == "__main__":
    main()
