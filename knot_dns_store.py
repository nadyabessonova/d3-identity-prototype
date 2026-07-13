"""Knot DNS-backed TrustfulStore using TXT records and TSIG updates."""

import shlex
import subprocess

import identity
import metrics
from store_interface import TrustfulStore


def _format_txt(fields):
    return "".join(f"{key}={value};" for key, value in fields.items())


def _parse_txt(txt_string):
    fields = {}
    for part in txt_string.split(";"):
        if not part:
            continue
        key, _, value = part.partition("=")
        fields[key] = value
    return fields


def _fqdn(name):
    return name if name.endswith(".") else f"{name}."


def _escape_txt(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


class KnotDNSStore(TrustfulStore):
    def __init__(
        self,
        server,
        zone,
        tsig_key_name,
        tsig_secret,
        ttl=60,
    ):
        self.server = server
        self.zone = _fqdn(zone)
        self.tsig_key_name = tsig_key_name.rstrip(".")
        self.tsig_secret = tsig_secret
        self.ttl = ttl

    def _sid_labels(self, identifier):
        # SHA-256 SID values are 64 chars, exceeding DNS's 63-octet label limit.
        return ".".join(
            identifier[index:index + 32]
            for index in range(0, len(identifier), 32)
        )

    def _record_name(self, identifier, namespace):
        return _fqdn(f"{self._sid_labels(identifier)}.{namespace}.{self.zone}")

    def _run_dig_txt(self, name):
        result = metrics.timed(
            "DNS TXT resolve",
            "knot_dns",
            "dns_txt_resolve",
            lambda: subprocess.run(
                [
                    "dig",
                    f"@{self.server}",
                    name,
                    "TXT",
                    "+short",
                    "+time=2",
                    "+tries=1",
                ],
                check=True,
                capture_output=True,
                text=True,
            ),
        )
        records = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                records.append("".join(shlex.split(line)))
        return records

    def _run_nsupdate_txt(self, name, value):
        update = (
            f"server {self.server}\n"
            f"zone {self.zone}\n"
            f"update delete {name} TXT\n"
            f'update add {name} {self.ttl} TXT "{_escape_txt(value)}"\n'
            "send\n"
        )
        result = metrics.timed(
            "DNS TXT update",
            "knot_dns",
            "dns_txt_update",
            lambda: subprocess.run(
                [
                    "nsupdate",
                    "-y",
                    f"hmac-sha256:{self.tsig_key_name}:{self.tsig_secret}",
                ],
                input=update,
                capture_output=True,
                text=True,
            ),
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(f"nsupdate failed for {name}: {detail}")
        return result

    def publish_identity(self, identifier, public_key, metadata=None, private_key=None):
        if public_key is not None:
            self._run_nsupdate_txt(
                self._record_name(identifier, "identity"),
                _format_txt(
                    {
                        "type": "identity",
                        "sid": identifier,
                        "alg": "ed25519",
                        "key": public_key,
                        "ver": "1",
                    }
                ),
            )

        if not metadata:
            return

        if "services" in metadata:
            value = _format_txt(
                {
                    "type": "registry",
                    "sid": identifier,
                    "services": ",".join(metadata.get("services", [])),
                    "ver": "1",
                }
            )
        else:
            value = _format_txt(
                {
                    "type": "agent",
                    "sid": identifier,
                    "provider": metadata.get("provider", ""),
                    "role": metadata.get("role", "service"),
                    "action": metadata.get("action", ""),
                    "in": metadata.get("in", ""),
                    "out": metadata.get("out", ""),
                    "endpoint": metadata.get("endpoint", ""),
                    "ver": "1",
                }
            )

        self._run_nsupdate_txt(self._record_name(identifier, "metadata"), value)

    def resolve_public_key(self, identifier):
        for record in self._run_dig_txt(self._record_name(identifier, "identity")):
            parsed = _parse_txt(record)
            if parsed.get("type") != "identity" or parsed.get("sid") != identifier:
                continue

            public_key = parsed.get("key")
            if identity.derive_sid(public_key) != identifier:
                raise ValueError("SID mismatch")
            return public_key
        return None

    def resolve_metadata(self, identifier):
        for record in self._run_dig_txt(self._record_name(identifier, "metadata")):
            parsed = _parse_txt(record)
            if parsed.get("sid") != identifier:
                continue
            if parsed.get("type") == "registry":
                return {
                    "services": [
                        sid.strip()
                        for sid in parsed.get("services", "").split(",")
                        if sid.strip()
                    ]
                }
            if parsed.get("type") == "agent":
                return parsed
        return None
