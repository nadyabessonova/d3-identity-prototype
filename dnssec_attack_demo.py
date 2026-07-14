"""Demonstrate DNSSEC rejection of a forged TXT response.

The experiment publishes one identity through the Knot DNS store, confirms that
normal DNSSEC-validated resolution succeeds, then simulates an on-path attacker
by altering the returned TXT RRset while leaving its original RRSIG unchanged.
DNSSEC validation must fail before any public key can be returned to IDAP.
"""

import os
import time

os.environ.setdefault("PERFORMANCE_RESULTS", "security_experiment_results.csv")

import dns.message
import dns.name
import dns.rdatatype
import dns.rrset

import config
import dnssec_resolver
import identity
from knot_dns_store import KnotDNSStore


def _escape_dns_txt(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _tamper_txt_response(response, target_name):
    forged = dns.message.from_wire(response.to_wire())
    target = dns.name.from_text(target_name)

    for index, rrset in enumerate(forged.answer):
        if rrset.name != target or rrset.rdtype != dns.rdatatype.TXT:
            continue

        original = b"".join(next(iter(rrset)).strings).decode()
        if "type=identity" in original:
            tampered = original.replace("type=identity", "type=forged", 1)
        else:
            tampered = original[:-1] + ("0" if original[-1] != "0" else "1")

        forged.answer[index] = dns.rrset.from_text(
            rrset.name,
            rrset.ttl,
            "IN",
            "TXT",
            f'"{_escape_dns_txt(tampered)}"',
        )
        return forged

    raise RuntimeError(f"No TXT RRset found to tamper for {target_name}")


def _new_store():
    return KnotDNSStore(
        server=config.KNOT_DNS_SERVER,
        zone=config.KNOT_DNS_ZONE,
        tsig_key_name=config.KNOT_DNS_TSIG_KEY,
        tsig_secret=config.KNOT_DNS_TSIG_SECRET,
        dnssec_validate=True,
        dnssec_trust_anchor=config.DNSSEC_TRUST_ANCHOR,
        dnssec_root=config.DNSSEC_ROOT,
        dns_timeout=config.DNS_TIMEOUT,
    )


def _publish_with_retry(store, agent, attempts=3):
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            store.publish_identity(agent["sid"], agent["public_key"])
            return
        except RuntimeError as exc:
            last_error = exc
            if attempt == attempts:
                break
            print(f"Publish attempt {attempt} failed; retrying...")
            time.sleep(1)
    raise last_error


def main():
    store = _new_store()
    existing_sid = os.environ.get("DNSSEC_ATTACK_SID")

    if existing_sid:
        sid = existing_sid
        expected_public_key = None
    else:
        agent = identity.generate_identity("DNSSECAttackTarget", mode="KNOT_DNS")
        sid = agent["sid"]
        expected_public_key = agent["public_key"]

        print("Publishing identity for DNSSEC attack experiment...")
        _publish_with_retry(store, agent)

    record_name = store._record_name(sid, "identity")

    print("\nNormal DNSSEC resolution:")
    resolved_key = store.resolve_public_key(sid)
    if expected_public_key is not None and resolved_key != expected_public_key:
        raise RuntimeError("Normal DNSSEC resolution returned an unexpected key")
    print("AUTHENTICATED")

    original_query = dnssec_resolver._query

    def forged_query(server, name, rdtype, timeout):
        response = original_query(server, name, rdtype, timeout)
        if rdtype == dns.rdatatype.TXT and dnssec_resolver._fqdn(name) == record_name:
            return _tamper_txt_response(response, record_name)
        return response

    print("\nForged TXT response:")
    dnssec_resolver._query = forged_query
    try:
        store.resolve_public_key(sid)
    except Exception as exc:
        print("REJECTED")
        print(f"Rejected by: {type(exc).__name__}")
        print("IDAP reached: False")
    else:
        raise RuntimeError("Forged TXT response was accepted")
    finally:
        dnssec_resolver._query = original_query


if __name__ == "__main__":
    main()
