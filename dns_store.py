"""DNS-backed TrustfulStore simulation using in-memory TXT records."""

import identity
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


class DNSStore(TrustfulStore):
    def __init__(self):
        self.records = {}

    def add_txt_record(self, name, txt_string):
        self.records.setdefault(name, []).append(txt_string)

    def query_txt(self, name):
        return self.records.get(name, [])

    def publish_identity(self, identifier, public_key, metadata=None):
        if public_key is not None:
            self.add_txt_record(
                identifier,
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

        if identifier == "_agents":
            self.add_txt_record("_agents", ",".join(metadata.get("services", [])))
            return

        fields = {
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
        self.add_txt_record(identifier, _format_txt(fields))

    def resolve_public_key(self, identifier):
        for record in self.query_txt(identifier):
            parsed = _parse_txt(record)
            if parsed.get("type") == "identity" and parsed.get("sid") == identifier:
                public_key = parsed.get("key")
                derived = identity.derive_sid(public_key)
                if derived != identifier:
                    raise ValueError("SID mismatch")
                return public_key
        return None

    def resolve_metadata(self, identifier):
        if identifier == "_agents":
            services = []
            for record in self.query_txt("_agents"):
                services.extend(sid.strip() for sid in record.split(",") if sid.strip())
            return {"services": services}

        for record in self.query_txt(identifier):
            parsed = _parse_txt(record)
            if parsed.get("type") == "agent" and parsed.get("sid") == identifier:
                return parsed
        return None
