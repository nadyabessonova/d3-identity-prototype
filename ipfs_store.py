"""IPFS/IPNS-backed TrustfulStore implementation.

The D3 IID is the protocol identity. Kubo/IPNS names are mutable-store
locators, kept separate in a local bootstrap registry:

    D3 IID -> IPNS key/name -> IPFS JSON document CID
"""

import json
import os
import uuid
from urllib import error, parse, request

import identity
import metrics
from store_interface import TrustfulStore


REGISTRY_ROOT = "iids"
SIGNATURE_PRIVATE_KEYS = {
    "_provider_private_key",
    "provider_private_key",
    "__provider_private_key",
}


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _read_json_file(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r") as f:
        return json.load(f)


def _write_json_file(path, data):
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp_path, path)


def _public_metadata(metadata):
    return {
        key: value
        for key, value in (metadata or {}).items()
        if key not in SIGNATURE_PRIVATE_KEYS
    }


def _provider_private_key(metadata):
    for key in SIGNATURE_PRIVATE_KEYS:
        if metadata and metadata.get(key):
            return metadata[key]
    return None


def _identity_payload(document):
    return {
        "type": document["type"],
        "iid": document["iid"],
        "public_key": document["public_key"],
        "encryption_public_key": document.get("encryption_public_key", ""),
        "ipns_name": document["ipns_name"],
        "version": document["version"],
    }


def _metadata_owner_payload(document):
    return {
        "type": document["type"],
        "iid": document["iid"],
        "public_key": document["public_key"],
        "metadata": document["metadata"],
        "ipns_name": document["ipns_name"],
        "version": document["version"],
    }


def _metadata_provider_payload(document):
    return {
        "type": document["type"],
        "iid": document["iid"],
        "provider": document["metadata"].get("provider", ""),
        "metadata": document["metadata"],
        "version": document["version"],
    }


class IPFSStore(TrustfulStore):
    def __init__(
        self,
        api_url="http://127.0.0.1:5001",
        registry_file="ipfs_store_registry.json",
        timeout=300,
        publish_lifetime="24h",
        publish_ttl="1m",
        allow_offline=False,
    ):
        self.api_url = api_url.rstrip("/")
        self.registry_file = registry_file
        self.timeout = timeout
        self.publish_lifetime = publish_lifetime
        self.publish_ttl = publish_ttl
        self.allow_offline = allow_offline
        self.registry = _read_json_file(self.registry_file, {})
        self.registry.setdefault("schema_version", 2)
        self.registry.setdefault(REGISTRY_ROOT, {})

    def _api_url(self, path, params=None):
        query = parse.urlencode(params or {})
        return f"{self.api_url}/api/v0/{path}" + (f"?{query}" if query else "")

    def _post(self, path, params=None, data=None, headers=None):
        req = request.Request(
            self._api_url(path, params),
            data=data,
            headers=headers or {},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read()
        except error.URLError as exc:
            raise RuntimeError(
                f"IPFS API call failed for {path}. Is the IPFS daemon running "
                f"at {self.api_url}?"
            ) from exc

    def _post_json(self, path, params=None, data=None, headers=None):
        raw = self._post(path, params=params, data=data, headers=headers)
        return json.loads(raw.decode())

    def _add_json(self, obj):
        def do_add():
            data = _canonical(obj).encode()
            boundary = uuid.uuid4().hex
            body = (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="file"; '
                'filename="object.json"\r\n'
                "Content-Type: application/json\r\n\r\n"
            ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
            headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
            result = self._post_json(
                "add",
                params={
                    "wrap-with-directory": "false",
                    "pin": "true",
                    "quiet": "true",
                },
                data=body,
                headers=headers,
            )
            return result["Hash"]

        return metrics.timed(
            "IPFS add JSON",
            "ipfs",
            "ipfs_add_json",
            do_add,
        )

    def _key_name(self, iid, namespace):
        return f"d3-{namespace}-{iid}"

    def _key_by_name(self, name):
        keys = self._post_json("key/list").get("Keys", [])
        for key in keys:
            if key.get("Name") == name:
                return key
        return None

    def _iid_entry(self, iid):
        return self.registry.setdefault(REGISTRY_ROOT, {}).setdefault(iid, {})

    def _namespace_entry(self, iid, namespace):
        iid_entry = self._iid_entry(iid)
        entry = iid_entry.get(namespace, {})
        key_name = entry.get("key_name") or self._key_name(iid, namespace)
        key = self._key_by_name(key_name)

        if key is None:
            key = metrics.timed(
                "IPFS key generation",
                "ipfs",
                "ipfs_key_gen",
                lambda: self._post_json(
                    "key/gen",
                    params={
                        "arg": key_name,
                        "type": "ed25519",
                    },
                ),
            )

        entry.update(
            {
                "key_name": key_name,
                "ipns_name": key["Id"],
            }
        )
        iid_entry[namespace] = entry
        _write_json_file(self.registry_file, self.registry)
        return entry

    def _publish_ipns(self, key_name, cid):
        params = {
            "arg": f"/ipfs/{cid}",
            "key": key_name,
            "lifetime": self.publish_lifetime,
            "ttl": self.publish_ttl,
        }
        if self.allow_offline:
            params["allow-offline"] = "true"

        return metrics.timed(
            "IPNS publish",
            "ipfs",
            "ipns_publish",
            lambda: self._post_json("name/publish", params=params),
        )

    def _resolve_ipns(self, iid, namespace):
        entry = self.registry.get(REGISTRY_ROOT, {}).get(iid, {}).get(namespace)
        if not entry:
            return None

        result = metrics.timed(
            "IPNS resolve",
            "ipfs",
            "ipns_resolve",
            lambda: self._post_json(
                "name/resolve",
                params={
                    "arg": f"/ipns/{entry['ipns_name']}",
                    "nocache": "true",
                },
            ),
        )
        return result["Path"]

    def _cat_json(self, path):
        raw = metrics.timed(
            "IPFS cat JSON",
            "ipfs",
            "ipfs_cat_json",
            lambda: self._post("cat", params={"arg": path}),
        )
        return json.loads(raw.decode())

    def _publish_document(self, iid, namespace, document):
        entry = self._namespace_entry(iid, namespace)
        document["ipns_name"] = entry["ipns_name"]
        cid = self._add_json(document)
        self._publish_ipns(entry["key_name"], cid)
        entry["cid"] = cid
        _write_json_file(self.registry_file, self.registry)
        return cid

    def _resolve_document(self, iid, namespace):
        path = self._resolve_ipns(iid, namespace)
        if not path:
            return None
        document = self._cat_json(path)
        if document.get("iid") != iid:
            raise ValueError("IID mismatch in IPFS document")
        return document

    def _public_key_matches_iid(self, public_key, iid):
        return identity.derive_iid(public_key) == iid

    def _sign_identity_document(self, document, private_key):
        if private_key:
            document["owner_signature"] = identity.sign(
                _canonical(_identity_payload(document)),
                private_key,
            )

    def _verify_identity_document(self, document):
        public_key = document["public_key"]
        if not self._public_key_matches_iid(public_key, document["iid"]):
            raise ValueError("IID mismatch")
        signature = document.get("owner_signature")
        if signature and not identity.verify(
            signature,
            _canonical(_identity_payload(document)),
            public_key,
        ):
            raise ValueError("Invalid IPFS identity owner signature")

    def _sign_metadata_document(self, document, owner_private_key, provider_private_key):
        if owner_private_key:
            document["owner_signature"] = identity.sign(
                _canonical(_metadata_owner_payload(document)),
                owner_private_key,
            )
        if provider_private_key:
            document["provider_signature"] = identity.sign(
                _canonical(_metadata_provider_payload(document)),
                provider_private_key,
            )

    def _verify_metadata_document(self, document):
        public_key = document["public_key"]
        if not self._public_key_matches_iid(public_key, document["iid"]):
            raise ValueError("IID mismatch")

        owner_signature = document.get("owner_signature")
        if owner_signature and not identity.verify(
            owner_signature,
            _canonical(_metadata_owner_payload(document)),
            public_key,
        ):
            raise ValueError("Invalid IPFS metadata owner signature")

        provider_signature = document.get("provider_signature")
        provider_iid = document["metadata"].get("provider")
        if provider_signature and provider_iid:
            provider_public_key = self.resolve_public_key(provider_iid)
            if not provider_public_key:
                raise ValueError("Provider public key not resolvable")
            if not identity.verify(
                provider_signature,
                _canonical(_metadata_provider_payload(document)),
                provider_public_key,
            ):
                raise ValueError("Invalid IPFS metadata provider signature")

    def publish_identity(self, identifier, public_key, metadata=None, private_key=None):
        identity_entry = self.registry.get(REGISTRY_ROOT, {}).get(
            identifier,
            {},
        ).get("identity", {})
        identity_already_published = bool(identity_entry.get("cid"))

        public_metadata = _public_metadata(metadata)
        if public_key is not None and not identity_already_published:
            identity_doc = {
                "type": "identity",
                "iid": identifier,
                "sid": identifier,
                "public_key": public_key,
                "encryption_public_key": public_metadata.get(
                    "encryption_public_key",
                    "",
                ),
                "version": 1,
            }
            entry = self._namespace_entry(identifier, "identity")
            identity_doc["ipns_name"] = entry["ipns_name"]
            self._sign_identity_document(identity_doc, private_key)
            cid = self._add_json(identity_doc)
            self._publish_ipns(entry["key_name"], cid)
            entry["cid"] = cid
            _write_json_file(self.registry_file, self.registry)

        if not metadata:
            return

        metadata_doc = {
            "type": "metadata",
            "iid": identifier,
            "sid": identifier,
            "public_key": public_key,
            "metadata": public_metadata,
            "version": 1,
        }
        entry = self._namespace_entry(identifier, "metadata")
        metadata_doc["ipns_name"] = entry["ipns_name"]
        self._sign_metadata_document(
            metadata_doc,
            private_key,
            _provider_private_key(metadata),
        )
        cid = self._add_json(metadata_doc)
        self._publish_ipns(entry["key_name"], cid)
        entry["cid"] = cid
        _write_json_file(self.registry_file, self.registry)

    def resolve_public_key(self, identifier):
        document = self._resolve_document(identifier, "identity")
        if not document:
            return None

        self._verify_identity_document(document)
        return document["public_key"]

    def resolve_metadata(self, identifier):
        document = self._resolve_document(identifier, "metadata")
        if not document:
            return None
        self._verify_metadata_document(document)
        return document.get("metadata", {})
