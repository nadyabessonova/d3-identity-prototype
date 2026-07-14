# D3 identity prototype

Repository accompanies the MSc thesis "Identity Management for AI Agents based on DNS" and implements the proof-of-concept realisation of the D3 framework.

Repository contains a minimal Python proof of concept for the agent identity, delegation, authorization, and secure communication flow as described in the paper "Titan: Towards Trustful and Resilient Internet. Deliverable D3: An Identity and Delegation Framework for Secure AI Agent
Communications".

The goal of the prototype is D3 paper conformance. It keeps the main concepts:

- Self-certifying agent identities based on SIDs.
- A Trustful Mutable Store abstraction for identity and metadata resolution.
- Broker-based service discovery.
- DAP capability creation and provider signatures.
- EncCAP representation as an encrypted signed capability.
- IDAP runtime authentication, authorization, replay protection, and session establishment.

## Mutable Store Modes

The same D3 protocol flow can run against four Trustful Mutable Store backends:

| `STORE_TYPE` | Mutable layer | Content layer | Purpose |
|---|---|---|---|
| `DNS_EMULATED` | In-memory DNS-like records | In-memory records | Baseline with no external services |
| `KNOT_DNS` | Real Knot DNS TXT records | DNS TXT records | Real DNS/DNSSEC-validated mutable store |
| `IPFS` | IPNS | IPFS immutable JSON objects | DNS-independent IPFS/IPNS mutable store experiment |
| `DNSLINK_IPFS` | Knot DNS DNSLink TXT records | IPFS immutable JSON objects | Hybrid design with DNSSEC-validated DNSLink pointers that avoids IPNS publication latency |

The D3 protocol components are the same across all modes. Only the store backend selected by `config.py` changes.

## Demo flow

Run `demo.py` for the end-to-end flow. It performs following steps:

1. Creates identities for a Client Provider, Service Provider, Client Agent, and Service Agent.
2. Publishes public keys and service metadata into the Trustful Mutable Store.
3. Uses the Broker to discover a service agent that supports the requested action.
4. Creates a DAP capability signed by both providers.
5. Wraps the signed capability as `EncCAP`, encrypted for the service agent.
6. Sends an IDAP request from the client agent to the service agent.
7. Verifies identities, provider signatures, action/target/expiry/quota, and replay controls.
8. Performs an ephemeral X25519 key exchange and derives a shared session key.
9. Demonstrates encrypted A2A communication with AES-GCM.
10. Shows that replayed and tampered requests are rejected.

## File Map

`identity.py`
Creates Ed25519 signing identities, derives SIDs from public keys, signs and verifies messages, and exposes an additional X25519 encryption public key used for `EncCAP`.

`store_interface.py`
Defines the abstract `TrustfulStore` interface: publish identity, resolve public key, and resolve metadata.

`config.py`
Selects and initializes the active Trustful Store implementation. The demo uses `config.get_store()` so the flow stays independent of the concrete backend.

`dns_store.py`
In-memory DNS-like implementation of the Trustful Mutable Store. This is the default store used by the demo and is reported in performance results as `DNS_EMULATED`.

`knot_dns_store.py`
Real Knot DNS-backed implementation of the Trustful Mutable Store. It publishes TXT records in a Knot-served DNS zone using TSIG-authenticated dynamic DNS updates and resolves TXT records through DNSSEC validation.

`dnssec_resolver.py`
Shared DNSSEC-validating TXT resolver for the real DNS-backed stores. It validates the zone DNSKEY RRset against the configured trust anchor, then validates TXT RRsets before returning them to the protocol code.

`ipfs_store.py`
Real IPFS/IPNS-backed implementation of the Trustful Mutable Store. It stores immutable identity and metadata JSON objects in IPFS and uses IPNS as the mutable pointer layer. Because D3 SIDs and IPNS names are separate namespaces, the prototype keeps a local `ipfs_store_registry.json` mapping from SID store keys to IPNS names. In `STORE_TYPE=IPFS`, the current identity layer uses its existing IPFS-compatible SID derivation. 

`dnslink_ipfs_store.py`
DNSLink/IPFS implementation of the Trustful Mutable Store. It stores immutable identity and metadata JSON objects in IPFS, then publishes DNSLink TXT records in Knot DNS that point to those IPFS CIDs. DNSLink reads are DNSSEC-validated. This avoids IPNS publication but still uses IPFS for immutable content storage.

`broker.py`
Looks up provider metadata in the store and returns service agent SIDs matching an action, input type, and output type.

`dap.py`
Creates the DAP capability, signs the canonical capability payload with both provider keys, verifies signatures, and wraps/unwraps the capability as `EncCAP`.

`idap.py`
Implements runtime IDAP checks: decrypts `EncCAP`, resolves SIDs, verifies DAP signatures, verifies the client request signature, enforces policy and replay/use controls, signs the transcript, and derives the session key.

`session.py`
Provides X25519 ephemeral session helpers and AES-GCM message encryption/decryption.

`demo.py`
Runs one full flow through the abstract store layer.

## Capability spec

DAP creates a signed capability containing:

```json
{
  "sp": "service-provider-sid",
  "cp": "client-provider-sid",
  "c1": "client-agent-sid",
  "s1": "service-agent-sid",
  "authority": {
    "action": "detect"
  },
  "control": {
    "expiry": "...",
    "quota": 5,
    "nonce": "..."
  },
  "sig_cp": "...",
  "sig_sp": "..."
}
```

The signed capability is then wrapped as `EncCAP`, encrypted to the service agent. IDAP decrypts it before validating signatures and policy constraints.

## How To Run

From the repository root:

```bash
python3 demo.py
```

No external services are required for the default demo. This uses the emulated DNS-like store and records the backend as `DNS_EMULATED`.

The four supported modes are:

```bash
STORE_TYPE=DNS_EMULATED python3 demo.py
STORE_TYPE=KNOT_DNS python3 demo.py
STORE_TYPE=IPFS python3 demo.py
STORE_TYPE=DNSLINK_IPFS python3 demo.py
```

To run the flow against the Knot DNS VM:

```bash
STORE_TYPE=KNOT_DNS python3 demo.py
```

Run this from a normal macOS terminal so `nsupdate` can reach the VM network interface.

Default Knot DNS settings are in `config.py`:

```text
KNOT_DNS_SERVER=192.168.1.121
KNOT_DNS_ZONE=example.com.
KNOT_DNS_TSIG_KEY=prototype-update
DNSSEC_VALIDATE=true
DNSSEC_TRUST_ANCHOR=trust-anchors/example.com.key
DNSSEC_ROOT=example.com.
DNS_TIMEOUT=2
```

These can be overridden with environment variables, including `KNOT_DNS_TSIG_SECRET`.

For the real DNS modes, TSIG is used only to authenticate dynamic DNS writes. Runtime DNS reads are validated with DNSSEC before the returned TXT values are accepted by the prototype. For temporary debugging only, DNSSEC read validation can be disabled with:

```bash
DNSSEC_VALIDATE=false STORE_TYPE=KNOT_DNS python3 demo.py
```

To run the same flow against a local IPFS/Kubo daemon:

```bash
STORE_TYPE=IPFS python3 demo.py
```

The IPFS daemon must already be running. If using a dedicated repository:

```bash
export IPFS_PATH=~/ipfs-d3-main
ipfs daemon
```

Then run the prototype from another terminal with the same `IPFS_PATH`:

```bash
export IPFS_PATH=~/ipfs-d3-main
STORE_TYPE=IPFS python3 demo.py
```

Default IPFS settings are in `config.py`:

```text
IPFS_API_URL=http://127.0.0.1:5001
IPFS_REGISTRY_FILE=ipfs_store_registry.json
IPFS_TIMEOUT=300
IPFS_PUBLISH_LIFETIME=24h
IPFS_PUBLISH_TTL=1m
IPFS_ALLOW_OFFLINE=false
```

To run the same flow with DNSLink over IPFS:

```bash
export IPFS_PATH=~/ipfs-d3-main
STORE_TYPE=DNSLINK_IPFS python3 demo.py
```

This backend requires both services:

```text
Knot DNS VM reachable through KNOT_DNS_* settings
Local IPFS/Kubo daemon reachable through IPFS_API_URL
```

The DNSLink/IPFS backend uses the existing `KNOT_DNS_*` and `IPFS_*` environment variables. It publishes TXT records containing values like:

```text
dnslink=/ipfs/<cid>
```

The mutable layer is DNS/Knot, while immutable JSON content is stored in IPFS.
The DNSLink TXT lookup is DNSSEC-validated before the IPFS CID is dereferenced.

## Expected Output

The exact SIDs, nonces, ciphertexts, signatures, and session keys change on every run. The important expected statuses are:

```text
Validation result:
AUTHORIZED

Replay result:
REJECTED

Transcript signature verified.
Match: True

Tampering result:
REJECTED
```

## Performance Measurements

Each `demo.py` execution appends timing rows to:

```text
performance_results.csv
```

The CSV contains:

```text
run_id,timestamp,backend,scenario,operation,duration_ms,status
```

Published experiment CSV artifacts are stored under `data/` in the GitHub repository.

To generate summary statistics:

```bash
python3 analyse_performance.py
```

The analysis output is split by backend, for example `=== METRICS (sec): KNOT_DNS ===`, `=== METRICS (sec): IPFS ===`, and `=== METRICS (sec): DNSLINK_IPFS ===`, plus backend-internal sections such as `=== KNOT DNS STATS (sec) ===`, `=== IPFS STATS (sec) ===`, and `=== DNSLINK IPFS STATS (sec) ===`.

To generate performance diagrams for all real backends:

```bash
python3 plot_performance.py
```

This writes PNG files to `performance_plots/` by default. In the GitHub repository, archived plot outputs are kept under `plots/`.

To generate readable comparison diagrams only for `KNOT_DNS` and `DNSLINK_IPFS`, excluding the much slower pure IPNS/IPFS results:

```bash
python3 plot_performance.py \
  --backends KNOT_DNS,DNSLINK_IPFS \
  --output-dir plots/performance_plots_dnslink_comparison
```

## Dependencies

The prototype requires Python 3, `cryptography`, and `dnspython`.

If dependencies are not installed:

```bash
python3 -m pip install cryptography dnspython
```

## Current Scope And Limitations

- Default mode uses the emulated in-memory Trustful Mutable Store and reports it as `DNS_EMULATED`.
- `STORE_TYPE=KNOT_DNS` uses a real Knot DNS server as the Trustful Mutable Store.
- `STORE_TYPE=IPFS` uses real IPFS immutable storage plus IPNS mutable pointers as the Trustful Mutable Store.
- `STORE_TYPE=DNSLINK_IPFS` uses Knot DNS as the mutable DNSLink pointer layer and IPFS as immutable JSON storage.
- `STORE_TYPE=KNOT_DNS` and `STORE_TYPE=DNSLINK_IPFS` use TSIG for authenticated DNS writes and DNSSEC validation for authenticated DNS reads.
- The IPFS backend uses `ipfs_store_registry.json` as a PoC bootstrap registry because D3/IPFS SIDs and IPNS names are different namespaces.
- The IPFS backend keeps the D3 protocol flow, but the SID-to-IPNS registry is a prototype bootstrap, not a fully decentralized discovery mechanism.
- Replay and quota state are held in process memory in `idap.py`.
- `EncCAP` uses an X25519/AES-GCM envelope.
- DAP is implemented at the capability-artifact level: the prototype creates the signed Cap/EncCAP that DAP is expected to produce, but it does not model a separate multi-message DAP negotiation exchange between providers. IDAP then validates that capability before A2A communication.

## TODO / Future Work

- Add signed metadata endorsements for the IPFS/IPNS trust-binding model described in the paper. The current IPFS backend demonstrates self-certifying identifiers and IPNS-based metadata resolution, but it does not yet add provider or broker signatures directly to the metadata object.
- A minimal extension would store metadata objects containing owner and provider endorsements, for example `owner_signature` and `provider_signature`, so a relying party can verify not only that the IID controls a public key, but also that a trusted Agent Provider or Broker endorses the agent metadata.
- This is different from DNSSEC-based trust binding. DNSSEC binds an IID/public key to an organization-controlled domain, while signed metadata endorsements preserve the DNS-independent IPFS/IPNS model and express trust through cryptographic attestations attached to IPFS metadata.
