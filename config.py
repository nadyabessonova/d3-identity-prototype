"""Store selection for the prototype."""

import os

from dns_store import DNSStore
from dnslink_ipfs_store import DNSLinkIPFSStore
from ipfs_store import IPFSStore
from knot_dns_store import KnotDNSStore


STORE_TYPE = os.environ.get("STORE_TYPE", "DNS_EMULATED")
IPFS_API_URL = os.environ.get("IPFS_API_URL", "http://127.0.0.1:5001")
IPFS_REGISTRY_FILE = os.environ.get("IPFS_REGISTRY_FILE", "ipfs_store_registry.json")
IPFS_TIMEOUT = int(os.environ.get("IPFS_TIMEOUT", "300"))
IPFS_PUBLISH_LIFETIME = os.environ.get("IPFS_PUBLISH_LIFETIME", "24h")
IPFS_PUBLISH_TTL = os.environ.get("IPFS_PUBLISH_TTL", "1m")
IPFS_ALLOW_OFFLINE = os.environ.get("IPFS_ALLOW_OFFLINE", "false").lower() in (
    "1",
    "true",
    "yes",
)
KNOT_DNS_SERVER = os.environ.get("KNOT_DNS_SERVER", "192.168.1.118")
KNOT_DNS_ZONE = os.environ.get("KNOT_DNS_ZONE", "example.com.")
KNOT_DNS_TSIG_KEY = os.environ.get("KNOT_DNS_TSIG_KEY", "prototype-update")
KNOT_DNS_TSIG_SECRET = os.environ.get(
    "KNOT_DNS_TSIG_SECRET",
    "hHbcm2AxO/U1FJHVHsldWsOjFUiww747mQ52pIbmgoY=",
)
_STORE = None


def get_store():
    global _STORE
    if _STORE is None:
        if STORE_TYPE in ("DNS", "DNS_EMULATED"):
            _STORE = DNSStore()
        elif STORE_TYPE == "IPFS":
            _STORE = IPFSStore(
                api_url=IPFS_API_URL,
                registry_file=IPFS_REGISTRY_FILE,
                timeout=IPFS_TIMEOUT,
                publish_lifetime=IPFS_PUBLISH_LIFETIME,
                publish_ttl=IPFS_PUBLISH_TTL,
                allow_offline=IPFS_ALLOW_OFFLINE,
            )
        elif STORE_TYPE == "KNOT_DNS":
            _STORE = KnotDNSStore(
                server=KNOT_DNS_SERVER,
                zone=KNOT_DNS_ZONE,
                tsig_key_name=KNOT_DNS_TSIG_KEY,
                tsig_secret=KNOT_DNS_TSIG_SECRET,
            )
        elif STORE_TYPE == "DNSLINK_IPFS":
            _STORE = DNSLinkIPFSStore(
                server=KNOT_DNS_SERVER,
                zone=KNOT_DNS_ZONE,
                tsig_key_name=KNOT_DNS_TSIG_KEY,
                tsig_secret=KNOT_DNS_TSIG_SECRET,
                api_url=IPFS_API_URL,
                timeout=IPFS_TIMEOUT,
            )
        else:
            raise ValueError(f"Unknown STORE_TYPE: {STORE_TYPE}")
    return _STORE


def reset_store():
    global _STORE
    _STORE = None
