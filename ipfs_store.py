"""IPFS/IPNS-backed TrustfulStore implementation.

The D3 SID is kept as the protocol identity. IPNS keys are used only as
mutable store pointers, with a local registry mapping SID values to IPNS names.
"""

import json
import os
import uuid
import base64
from urllib import error, parse, request

import identity
import metrics
from store_interface import TrustfulStore


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

    def _post_json(self, path, params=None, data=None, headers=None):
        raw = self._post(path, params=params, data=data, headers=headers)
        return json.loads(raw.decode())

    def _key_name(self, sid):
        return f"d3-{sid}"

    def _key_by_name(self, name):
        keys = self._post_json("key/list").get("Keys", [])
        for key in keys:
            if key.get("Name") == name:
                return key
        return None

    def _ensure_ipns_key(self, sid):
        entry = self.registry.get(sid)
        key_name = entry.get("key_name") if entry else self._key_name(sid)
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

        self.registry[sid] = {
            "key_name": key_name,
            "ipns_name": key["Id"],
        }
        _write_json_file(self.registry_file, self.registry)
        return self.registry[sid]

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

    def _resolve_ipns(self, sid):
        entry = self.registry.get(sid)
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

    def _publish_document(self, store_key, document):
        cid = self._add_json(document)
        entry = self._ensure_ipns_key(store_key)
        self._publish_ipns(entry["key_name"], cid)
        self.registry[store_key]["cid"] = cid
        _write_json_file(self.registry_file, self.registry)
        return cid

    def _resolve_document(self, store_key, expected_sid):
        path = self._resolve_ipns(store_key)
        if not path:
            return None
        document = self._cat_json(path)
        if document.get("sid") != expected_sid:
            raise ValueError("SID mismatch in IPFS document")
        return document

    def _public_key_matches_sid(self, public_key, sid):
        if identity.derive_sid(public_key) == sid:
            return True
        public_key_bytes = base64.b64decode(public_key)
        return identity.derive_peer_id(public_key_bytes) == sid

    def publish_identity(self, identifier, public_key, metadata=None, private_key=None):
        identity_store_key = f"{identifier}:identity"
        identity_already_published = bool(
            self.registry.get(identity_store_key, {}).get("cid")
        )

        if public_key is not None and not identity_already_published:
            identity_doc = {
                "type": "identity",
                "sid": identifier,
                "public_key": public_key,
                "encryption_public_key": (metadata or {}).get(
                    "encryption_public_key",
                    "",
                ),
                "version": 1,
            }
            self._publish_document(identity_store_key, identity_doc)

        if not metadata:
            return

        metadata_doc = {
            "type": "metadata",
            "sid": identifier,
            "metadata": metadata,
            "version": 1,
        }
        self._publish_document(f"{identifier}:metadata", metadata_doc)

    def resolve_public_key(self, identifier):
        document = self._resolve_document(f"{identifier}:identity", identifier)
        if not document:
            return None

        public_key = document["public_key"]
        if not self._public_key_matches_sid(public_key, identifier):
            raise ValueError("SID mismatch")
        return public_key

    def resolve_metadata(self, identifier):
        document = self._resolve_document(f"{identifier}:metadata", identifier)
        if not document:
            return None
        return document.get("metadata", {})
