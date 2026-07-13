"""DNSLink/IPFS-backed TrustfulStore.

Knot DNS provides the mutable DNSLink pointer and IPFS stores immutable JSON
documents. This avoids IPNS publication while preserving the store interface.
"""

import base64
import json
import shlex
import subprocess
import uuid
from urllib import error, parse, request

import identity
import metrics
from store_interface import TrustfulStore


def _canonical(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _fqdn(name):
    return name if name.endswith(".") else f"{name}."


def _escape_txt(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


class DNSLinkIPFSStore(TrustfulStore):
    def __init__(
        self,
        server,
        zone,
        tsig_key_name,
        tsig_secret,
        api_url="http://127.0.0.1:5001",
        ttl=60,
        timeout=300,
    ):
        self.server = server
        self.zone = _fqdn(zone)
        self.tsig_key_name = tsig_key_name.rstrip(".")
        self.tsig_secret = tsig_secret
        self.api_url = api_url.rstrip("/")
        self.ttl = ttl
        self.timeout = timeout
        self.published_identities = set()

    def _labels(self, identifier):
        # Keep labels comfortably below DNS's 63-octet label limit.
        return ".".join(
            identifier[index:index + 32]
            for index in range(0, len(identifier), 32)
        )

    def _record_name(self, identifier, namespace):
        return _fqdn(f"_dnslink.{self._labels(identifier)}.{namespace}.{self.zone}")

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
            "dnslink_ipfs",
            "ipfs_add_json",
            do_add,
        )

    def _cat_json(self, path):
        raw = metrics.timed(
            "IPFS cat JSON",
            "dnslink_ipfs",
            "ipfs_cat_json",
            lambda: self._post("cat", params={"arg": path}),
        )
        return json.loads(raw.decode())

    def _run_nsupdate_txt(self, name, value):
        update = (
            f"server {self.server}\n"
            f"zone {self.zone}\n"
            f"update delete {name} TXT\n"
            f'update add {name} {self.ttl} TXT "{_escape_txt(value)}"\n'
            "send\n"
        )
        result = metrics.timed(
            "DNSLink TXT update",
            "dnslink_ipfs",
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

    def _run_dig_txt(self, name):
        result = metrics.timed(
            "DNSLink TXT resolve",
            "dnslink_ipfs",
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

    def _publish_document(self, identifier, namespace, document):
        cid = self._add_json(document)
        self._run_nsupdate_txt(
            self._record_name(identifier, namespace),
            f"dnslink=/ipfs/{cid}",
        )
        return cid

    def _resolve_document(self, identifier, namespace):
        for record in self._run_dig_txt(self._record_name(identifier, namespace)):
            if not record.startswith("dnslink=/ipfs/"):
                continue
            document = self._cat_json(record.removeprefix("dnslink="))
            if document.get("sid") != identifier:
                raise ValueError("SID mismatch in DNSLink/IPFS document")
            return document
        return None

    def _public_key_matches_sid(self, public_key, sid):
        if identity.derive_sid(public_key) == sid:
            return True
        public_key_bytes = base64.b64decode(public_key)
        return identity.derive_peer_id(public_key_bytes) == sid

    def publish_identity(self, identifier, public_key, metadata=None, private_key=None):
        if public_key is not None and identifier not in self.published_identities:
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
            self._publish_document(identifier, "identity", identity_doc)
            self.published_identities.add(identifier)

        if not metadata:
            return

        metadata_doc = {
            "type": "metadata",
            "sid": identifier,
            "metadata": metadata,
            "version": 1,
        }
        self._publish_document(identifier, "metadata", metadata_doc)

    def resolve_public_key(self, identifier):
        document = self._resolve_document(identifier, "identity")
        if not document:
            return None

        public_key = document["public_key"]
        if not self._public_key_matches_sid(public_key, identifier):
            raise ValueError("SID mismatch")
        return public_key

    def resolve_metadata(self, identifier):
        document = self._resolve_document(identifier, "metadata")
        if not document:
            return None
        return document.get("metadata", {})
