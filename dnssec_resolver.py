"""DNSSEC-validating TXT resolver for the real DNS-backed stores."""

import re

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.rcode
import dns.rdataclass
import dns.rdataset


class DNSSECValidationError(RuntimeError):
    """Raised when a DNS answer cannot be validated with the configured anchor."""


def _fqdn(name):
    return name if name.endswith(".") else f"{name}."


def _query(server, name, rdtype, timeout):
    query = dns.message.make_query(name, rdtype, want_dnssec=True)
    try:
        response = dns.query.udp(query, server, timeout=timeout)
        if response.flags & dns.flags.TC:
            response = dns.query.tcp(query, server, timeout=timeout)
    except dns.exception.Timeout as exc:
        raise DNSSECValidationError(f"DNS query timed out for {name} {rdtype}") from exc

    rcode = response.rcode()
    if rcode != dns.rcode.NOERROR:
        raise DNSSECValidationError(
            f"DNS query failed for {name} {rdtype}: {dns.rcode.to_text(rcode)}"
        )
    return response


def _find_rrset(section, name, rdtype, covers=dns.rdatatype.NONE):
    target_name = dns.name.from_text(_fqdn(name))
    for rrset in section:
        if rrset.name != target_name:
            continue
        if rrset.rdtype != rdtype:
            continue
        if rdtype == dns.rdatatype.RRSIG and rrset.covers != covers:
            continue
        return rrset
    return None


def _parse_trust_anchor(path, root):
    """Parse a BIND trusted-keys style file containing one DNSKEY anchor."""
    root_name = dns.name.from_text(_fqdn(root))
    with open(path, "r", encoding="utf-8") as anchor_file:
        text = anchor_file.read()

    pattern = re.compile(
        r"(?P<name>[A-Za-z0-9_.-]+)\s+"
        r"(?P<flags>\d+)\s+"
        r"(?P<protocol>\d+)\s+"
        r"(?P<algorithm>\d+)\s+"
        r'"(?P<key>[^"]+)"'
    )
    for match in pattern.finditer(text):
        name = dns.name.from_text(_fqdn(match.group("name")))
        if name != root_name:
            continue
        rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY)
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.DNSKEY,
            " ".join(
                [
                    match.group("flags"),
                    match.group("protocol"),
                    match.group("algorithm"),
                    match.group("key"),
                ]
            ),
            origin=root_name,
        )
        rdataset.add(rdata)
        return rdataset

    raise DNSSECValidationError(f"No DNSKEY trust anchor found for {root_name}")


def _validated_dnskeys(server, root, trust_anchor_file, timeout):
    root_name = dns.name.from_text(_fqdn(root))
    trust_anchor = _parse_trust_anchor(trust_anchor_file, root)
    response = _query(server, root, dns.rdatatype.DNSKEY, timeout)
    dnskey_rrset = _find_rrset(response.answer, root, dns.rdatatype.DNSKEY)
    dnskey_rrsig = _find_rrset(
        response.answer,
        root,
        dns.rdatatype.RRSIG,
        covers=dns.rdatatype.DNSKEY,
    )
    if dnskey_rrset is None or dnskey_rrsig is None:
        raise DNSSECValidationError(f"Missing DNSKEY/RRSIG answer for {root_name}")

    dns.dnssec.validate(dnskey_rrset, dnskey_rrsig, {root_name: trust_anchor})
    return dnskey_rrset


def resolve_txt(
    server,
    name,
    trust_anchor_file,
    root,
    timeout=2,
):
    """Resolve TXT records and validate the positive answer with DNSSEC."""
    dnskeys = _validated_dnskeys(server, root, trust_anchor_file, timeout)
    response = _query(server, name, dns.rdatatype.TXT, timeout)
    txt_rrset = _find_rrset(response.answer, name, dns.rdatatype.TXT)
    txt_rrsig = _find_rrset(
        response.answer,
        name,
        dns.rdatatype.RRSIG,
        covers=dns.rdatatype.TXT,
    )

    if txt_rrset is None:
        raise DNSSECValidationError(f"No DNSSEC-validated TXT answer for {name}")
    if txt_rrsig is None:
        raise DNSSECValidationError(f"Missing TXT RRSIG for {name}")

    root_name = dns.name.from_text(_fqdn(root))
    dns.dnssec.validate(txt_rrset, txt_rrsig, {root_name: dnskeys})

    records = []
    for rdata in txt_rrset:
        records.append(b"".join(rdata.strings).decode())
    return records
