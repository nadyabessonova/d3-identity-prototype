# Titan prototype

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
Creates Ed25519 signing identities, derives compact D3 identifiers as `base32(ripemd160(sha256(P)))`, signs and verifies messages, and exposes an additional X25519 encryption public key used for `EncCAP`. In `STORE_TYPE=IPFS`, this identifier is treated as the D3 IID.

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
Real IPFS/IPNS-backed implementation of the Trustful Mutable Store. It stores immutable identity and metadata JSON objects in IPFS and uses IPNS as the mutable pointer layer. The D3 IID is the protocol identity, Kubo/IPNS names are mutable-store locators. The local `ipfs_store_registry.json` bootstrap registry maps `D3 IID -> IPNS key/name -> IPFS CID`. IPFS identity and metadata objects are owner-signed; service metadata can also be provider-signed as a trust endorsement.

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

`dnssec_attack_demo.py`
Runs a focused DNS-layer security experiment. It publishes an identity, confirms normal DNSSEC-validated TXT resolution succeeds, then simulates a forged TXT response by modifying the returned RRset while keeping the original RRSIG. The resolver rejects the response before any public key is returned to IDAP.

`artifacts/`
Contains generated experiment outputs, plots, thesis tables, and archived stale files. It is separated from the source code so the current prototype remains easy to inspect.

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

For the real DNS modes, TSIG is used only to authenticate dynamic DNS writes. Runtime DNS reads are validated with DNSSEC before the returned TXT values are accepted by the prototype. 

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

The mutable layer is Knot DNS, immutable JSON content is stored in IPFS.
The DNSLink TXT lookup is DNSSEC-validated before the IPFS CID is dereferenced.

## DNSSEC Attack Experiment

To demonstrate that DNSSEC validation is active rather than only present in the successful path:

```bash
python3 dnssec_attack_demo.py
```

Expected result:

```text
Normal DNSSEC resolution:
AUTHENTICATED

Forged TXT response:
REJECTED
IDAP reached: False
```

The attack script simulates a forged DNS TXT answer by changing the TXT payload after it has been received from Knot DNS while leaving the original DNSSEC signature unchanged. Validation fails in `dnssec_resolver.py`, before `idap.py` can receive or trust a public key.

## HTTP Gateway For n8n

`d3_gateway.py` exposes the existing D3 flow through a lightweight FastAPI entry point. It does not call `demo.main()` and does not reimplement DAP, IDAP, or broker discovery. It orchestrates the existing modules as reusable libraries.

The gateway is the single public entry point for orchestration tools such as n8n:

```text
n8n -> POST /invoke -> D3 Gateway -> Broker -> DAP -> IDAP -> Protected Service
```

The protected services are registered locally, but they are still published into the configured Trustful Store and discovered through `broker.discover()` before DAP/IDAP execution:

| Action | Input type | Output type | Service |
| --- | --- | --- | --- |
| `search_flights` | `flight_search_request` | `flight_offer` | Flight Search Agent |
| `authorize_payment` | `payment_request` | `payment_authorization` | Payment Authorization Agent |
| `purchase_ticket` | `ticket_purchase_request` | `ticket_confirmation` | Ticket Purchase Agent |
| `send_notification` | `notification_request` | `notification_status` | Notification Agent |

The gateway publishes multiple providers, each with its own identity and service registry:

| Provider | Services |
| --- | --- |
| `TravelProvider` | `search_flights`, `purchase_ticket` |
| `PaymentProvider` | `authorize_payment` |
| `NotificationProvider` | `send_notification` |

The travel services live in `services/` and expose `execute(payload)`. The gateway dispatches through `services/registry.py`, not through independent REST services. Provider layout is declared in `services/providers.py`.

Install gateway dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Run the gateway:

```bash
uvicorn d3_gateway:app --reload
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

The client does not need to know which provider implements the action. If `input_type` and `output_type` are omitted, the gateway infers them from the service registry before calling Broker discovery.

Invoke the Travel Assistant flight search:

```bash
curl -X POST http://127.0.0.1:8000/invoke \
  -H "Content-Type: application/json" \
  -d '{
    "action": "search_flights",
    "payload": {
      "origin": "HEL",
      "destination": "CDG",
      "date": "2026-09-15",
      "airlines": ["Lufthansa", "Air France"],
      "max_price": 300
    }
  }'
```

Invoke the protected payment authorization:

```bash
curl -X POST http://127.0.0.1:8000/invoke \
  -H "Content-Type: application/json" \
  -d '{
    "action": "authorize_payment",
    "payload": {
      "merchant": "Air France",
      "airline": "Air France",
      "flight": "AF1177",
      "amount": 240,
      "currency": "EUR"
    }
  }'
```

The successful gateway response contains this protected service result under `service_response`:

```json
{
  "authorized": true,
  "authorization_id": "AUTH-123456",
  "purchase_authorization": {
    "type": "D3-EncCAP",
    "target_action": "purchase_ticket",
    "constraints": {
      "authorization_id": { "eq": "AUTH-123456" },
      "flight": { "eq": "AF1177" },
      "airline": { "eq": "Air France" },
      "amount": { "lte": 240 },
      "currency": { "eq": "EUR" }
    }
  }
}
```

`purchase_authorization.enc_cap` is a delegated DAP capability encrypted to the Ticket Purchase Agent. n8n should pass this object to the next `purchase_ticket` invocation.

Invoke ticket purchase with the delegated authorization:

```bash
curl -X POST http://127.0.0.1:8000/invoke \
  -H "Content-Type: application/json" \
  -d '{
    "action": "purchase_ticket",
    "payload": {
      "flight": "AF1177",
      "airline": "Air France",
      "amount": 240,
      "currency": "EUR",
      "authorization_id": "AUTH-123456",
      "purchase_authorization": {
        "...": "use the purchase_authorization object returned by authorize_payment"
      }
    }
  }'
```

For `purchase_ticket`, the gateway does not mint a fresh capability. It presents the delegated EncCAP returned by `authorize_payment`; IDAP decrypts it, verifies the DAP signatures, checks expiry/replay/quota, and evaluates the signed constraints against the ticket purchase payload before the Ticket Purchase Agent executes.

Demonstrate generic IDAP constraint rejection after successful discovery:

```bash
curl -i -X POST http://127.0.0.1:8000/invoke \
  -H "Content-Type: application/json" \
  -d '{
    "action": "authorize_payment",
    "payload": {
      "merchant": "Air France",
      "amount": 550,
      "currency": "EUR"
    }
  }'
```

Expected result:

```text
HTTP/1.1 403 Forbidden
```

In this case Broker discovery succeeds for `authorize_payment`, DAP creates and signs a capability, and IDAP rejects the request because the signed generic constraint `amount <= 300` is not satisfied.

Ticket purchase also rejects if the delegated authorization is missing or if the purchase request changes the authorized flight, airline, amount, currency, or authorization ID. This demonstrates end-to-end delegated authorization across cooperating providers without adding a separate payment-token mechanism.

### Generic Capability Constraints

`dap.py` supports optional generic constraints inside the signed `authority` object:

```json
{
  "authority": {
    "action": "authorize_payment",
    "constraints": {
      "merchant": { "in": ["Lufthansa", "Air France"] },
      "amount": { "lte": 300 },
      "currency": { "eq": "EUR" }
    }
  }
}
```

`idap.py` evaluates those constraints against `request.payload` before the protected service is executed. Supported operators are `eq`, `neq`, `in`, `not_in`, `lte`, `lt`, `gte`, `gt`, and `exists`. The constraint mechanism is deliberately scenario-independent: the payment example uses it for merchant and amount limits, but the same format can constrain other payload fields in other applications.

When n8n runs in Docker, use the host gateway URL from the n8n HTTP Request node:

```text
http://host.docker.internal:8000/invoke
```

The gateway initializes the configured Trustful Store, publishes the demonstration identities and metadata, discovers a service through `broker.discover()`, creates and encrypts a DAP capability, performs IDAP authorization, verifies the transcript, derives the session key, and sends the service payload over the existing encrypted A2A channel. n8n only sees a normal HTTP request and JSON response.

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
artifacts/performance/raw/performance_results.csv
```

The CSV contains:

```text
run_id,timestamp,backend,scenario,operation,duration_ms,status
```

To generate summary statistics:

```bash
python3 analysis/analyse_performance.py
```

The analysis output is split by backend, for example `=== METRICS (sec): KNOT_DNS ===`, `=== METRICS (sec): IPFS ===`, and `=== METRICS (sec): DNSLINK_IPFS ===`, plus backend-internal sections such as `=== KNOT DNS STATS (sec) ===`, `=== IPFS STATS (sec) ===`, and `=== DNSLINK IPFS STATS (sec) ===`. The default CSV outputs are written to:

```text
artifacts/performance/statistics/
```

To generate performance diagrams for all real backends:

```bash
python3 analysis/plot_performance.py
```

This writes PNG files to:

```text
artifacts/performance/plots/performance_plots/
```

To generate readable comparison diagrams only for `KNOT_DNS` and `DNSLINK_IPFS`, excluding IPNS/IPFS results:

```bash
python3 analysis/plot_performance.py \
  --backends KNOT_DNS,DNSLINK_IPFS \
  --output-dir artifacts/performance/plots/performance_plots_dnslink_comparison
```

To generate thesis-ready LaTeX phase tables:

```bash
python3 analysis/generate_thesis_phase_tables.py
```

This writes:

```text
artifacts/thesis/thesis_phase_tables_d3_conformant.tex
```

## Artifact Layout

Generated outputs are organized as follows:

```text
artifacts/performance/raw/          raw timing CSV files
artifacts/performance/statistics/   aggregated performance statistics
artifacts/performance/plots/        generated performance diagrams
artifacts/security/                 DNSSEC attack / security experiment results
artifacts/thesis/                   LaTeX-ready thesis tables
artifacts/archive/stale-root/       old scratch files retained for provenance
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
- DNS-backed modes now use the D3 compact SID construction `base32(ripemd160(sha256(P)))`, which fits in a single DNS label.
- The IPFS backend uses D3-style IIDs as protocol identities and `ipfs_store_registry.json` as a PoC bootstrap registry mapping IIDs to IPNS locators.
- The IPFS backend keeps the D3 protocol flow, but the SID-to-IPNS registry is a prototype bootstrap, not a fully decentralized discovery mechanism.
- Pure IPFS identity and metadata documents include owner signatures, and service metadata may include provider endorsement signatures. These signatures establish metadata trust binding and are separate from DAP runtime capabilities.
- Replay and quota state are held in process memory in `idap.py`.
- `EncCAP` uses an X25519/AES-GCM envelope.
- DAP is implemented at the capability-artifact level: the prototype creates the signed Cap/EncCAP that DAP is expected to produce, but it does not model a separate multi-message DAP negotiation exchange between providers. IDAP then validates that capability before A2A communication.

## TODO / Future Work

- Optionally add broker endorsement signatures to the IPFS/IPNS trust-binding model. The current IPFS backend stores and verifies owner signatures and provider endorsement signatures, but not broker signatures.
- This is different from DNSSEC-based trust binding. DNSSEC binds an IID/public key to an organization-controlled domain, while signed metadata endorsements preserve the DNS-independent IPFS/IPNS model and express trust through cryptographic attestations attached to IPFS metadata.
