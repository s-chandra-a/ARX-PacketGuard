# ARX-PacketGuard: Secure Chat & Network Traffic Inspector

**ARX-PacketGuard** is an interactive, educational Information Security classroom demonstration platform. It combines two core security domains into an integrated, projection-ready web application:

1. **ARX (Authenticated Ratcheted Exchange):** An end-to-end encrypted, zero-knowledge one-to-one messaging system featuring **X25519**, **NIST FIPS 203 ML-KEM-768 Hybrid Post-Quantum Key Establishment**, **HKDF-SHA-256** directional chains, **AES-256-GCM** authenticated encryption with canonical Authenticated Additional Data (AAD) headers, per-message key evolution, periodic epoch changes, stateful replay prevention, and bounded out-of-order message handling.
2. **PacketGuard:** An independent traffic monitoring engine and rule-based heuristic anomaly detector that analyzes network packet metadata (**Possible Port Scan**, **Flow-Correlated Possible SYN Flood**, **Possible ARP Mapping Conflict**, and **Suspicious DNS Activity**) and visualizes protocol metrics using **Recharts**.

> **Educational Scope Disclaimer:** This software is a pedagogical prototype created for teaching applied cryptography, network packet inspection, and heuristic detection in computer security courses. It is not an audited production secure messaging product, does not claim Signal equivalence, and demonstrates why deterministic epoch ratcheting provides forward key separation but not post-compromise security (PCS) or guaranteed RAM wiping in managed runtimes (JavaScript/Python).

---

## Table of Contents

- [Key Features & What It Does](#key-features--what-it-does)
- [System Architecture](#system-architecture)
- [Prerequisites](#prerequisites)
- [Installation & Quick Start](#installation--quick-start)
- [Running Tests](#running-tests)
- [How to Run Alice and Bob](#how-to-run-alice-and-bob)
- [Detailed View & Function Walkthrough](#detailed-view--function-walkthrough)
  - [1. Overview Dashboard](#1-overview-dashboard)
  - [2. Chat & Endpoints](#2-chat--endpoints)
  - [3. Relay Inspector](#3-relay-inspector)
  - [4. Packet Dashboard (with Recharts)](#4-packet-dashboard-with-recharts)
  - [5. Experiments, Demo Script & Viva Guide](#5-experiments-demo-script--viva-guide)
- [Interactive Security Experiments](#interactive-security-experiments)
- [Detection Rules & Heuristics](#detection-rules--heuristics)
- [Local Python Kit & Standalone Capture Worker](#local-python-kit--standalone-capture-worker)
- [API Endpoints Reference](#api-endpoints-reference)
- [Troubleshooting & FAQ](#troubleshooting--faq)

---

## Key Features & What It Does

- **Real Endpoint Cryptography:** Encryption and decryption occur strictly inside the browser endpoints (Alice and Bob). The relay and packet monitor never have access to private keys, session secrets, message keys, or decrypted message plaintext.
- **Classical & Post-Quantum Hybrid Modes:**
  - `CLASSICAL_X25519`: Pure Diffie-Hellman over Curve25519 + HKDF-SHA-256 + AES-256-GCM.
  - `HYBRID_X25519_MLKEM768`: Combines X25519 with real NIST FIPS 203 ML-KEM-768 (Kyber) post-quantum encapsulation and decapsulation (1184-byte public key, 1088-byte ciphertext, combined 64-byte secret material).
  - `LOCAL_PLAINTEXT_BASELINE`: Unencrypted comparison baseline prominently flagged as an educational demo.
- **Double Ratchet Principles & Key Evolution:**
  - Separate directional sending/receiving chains (`A2B` and `B2A`).
  - One-way per-message HKDF ratcheting: identical plaintext messages produce completely unique keys, nonces, and ciphertexts.
  - Local-only educational SHA-256 key fingerprints verify ratcheting without leaking secret keys.
- **Configurable Epoch Transitions:** Epoch evolution advances the root secret every $N$ messages (e.g. 3, 5, or 10 messages).
- **Integrity & Replay Protection:**
  - Canonical UTF-8 serialized AAD headers bind protocol version, session ID, sender, recipient, direction, epoch, message number, and nonce into AES-256-GCM.
  - State committed **only after** successful authentication. Tampered messages fail with `AUTH_FAILED` and do not break the receiver's state.
  - Explicit replay detection (`REPLAY_DETECTED`), distinct from authentication failure.
  - Bounded out-of-order message cache (`MAX_SKIP = 32`).
- **Autonomous Local Bob Bot:**
  - Local rule-based command responder (`hello`, `time`, `help`, `echo <text>`).
  - Decrypts at Bob's endpoint, generates a reply, and encrypts with Bob's sending ratchet before sending through the relay.
- **Untrusted Ciphertext-Only Relay Inspector:**
  - Inspects the exact serialized envelope received by the relay server.
  - Confirms zero plaintext exists in SQLite storage.
- **Independent Packet Traffic Inspection & Heuristic Anomaly Detection:**
  - Evaluates network metadata independent of ARX application layers.
  - Recharts interactive Protocol Distribution pie chart (`TCP`, `HTTP`, `DNS`, `ARP`, `UDP`, `TLS`).
  - Byte-rate and packets-per-second (PPS) time-series distribution charts.
  - 4 configurable heuristic detection rules with sliding windows, cooldown suppression, and flow correlation.
- **Complete Classroom Tooling:**
  - 5-minute timed presentation demo script.
  - Comprehensive Viva Voce defense Q&A.
  - Automated 15-test acceptance test suite.
  - Built-in downloadable local Python Flask backend and standalone Pyshark/TShark capture worker.

---

## System Architecture

The application is structured into three logically isolated components:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ARX-PacketGuard Ecosystem                       │
└────────────────────────────────────────────────────────────────────────┘

  [ ALICE CLIENT ]                                [ BOB CLIENT ]
 (127.0.0.1:54110)                               (127.0.0.1:54120)
  - Holds Alice private keys                      - Holds Bob private keys
  - A2B Sending Ratchet                           - B2A Sending Ratchet
  - B2A Receiving Ratchet                         - A2B Receiving Ratchet
  - Encrypts before sending                       - Decrypts upon receive
  - Verifies AAD & GCM Tag                        - Verifies AAD & GCM Tag
  - Tracks Seen Keys & Watermark                  - Tracks Seen Keys & Watermark
         │                                               ▲
         │ Encrypted Envelope                            │ Encrypted Envelope
         ▼                                               │
 ┌───────────────────────────────────────────────────────────────┐
 │               UNTRUSTED RELAY SERVER (Port 3000)              │
 │                                                               │
 │  - Express & SQLite (`relay_envelopes`, `conversations`)       │
 │  - Enforces conversation membership authorization (403 check) │
 │  - Zero knowledge: No private keys, message keys, or plaintexts│
 │  - Armed Tamper Intervention (Bit-flip, header mod, tag drop) │
 │  - Logs loopback metadata packets to `packet_metadata`        │
 └───────────────────────────────────────────────────────────────┘
                                 │
                                 ▼ (Metadata stream)
 ┌───────────────────────────────────────────────────────────────┐
 │                   PACKETGUARD MONITOR ENGINE                  │
 │                                                               │
 │  - Independent network packet inspection                      │
 │  - Evaluates captured metadata (IP, port, flags, length, DNS) │
 │  - Recharts Protocol Distribution & Throughput charts         │
 │  - Flow-correlated SYN flood, port scan, ARP & DNS heuristics │
 │  - Recorded PCAP traces, Synthetic fixtures, or Live Worker   │
 └───────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

- **Node.js:** Version 20.x or higher (Node 22 LTS recommended).
- **npm:** Version 9.x or higher.
- *(Optional for Live Capture)* **Python:** Version 3.10+ and Wireshark / TShark.

---

## Installation & Quick Start

### 1. Clone & Install Dependencies

```bash
git clone <repository-url>
cd arx-packetguard
npm install
```

### 2. Start the Development Server

```bash
npm run dev
```

The Express backend and Vite frontend will compile and listen on **`http://localhost:3000`**.

### 3. Build for Production

```bash
npm run build
npm start
```

---

## Running Tests

ARX-PacketGuard includes a 15-point automated acceptance test suite written with Vitest that verifies all cryptographic, ratcheting, replay, tamper, relay, and detection requirements:

```bash
npm test
```

### Verified Test Criteria
1. Full encrypt/decrypt round trip including multi-script Unicode.
2. Derivation of unique message keys, nonces, and ciphertexts for repeated identical plaintexts.
3. Domain-separated directional chains (`A2B` vs. `B2A`).
4. Rejection of ciphertext bit flips, tag corruption, and authenticated header modifications.
5. Strict replay rejection and discrimination between `REPLAY_DETECTED` and `AUTH_FAILED`.
6. Configurable epoch boundary transitions and key ratcheting.
7. Bounded out-of-order message handling (`MAX_SKIP = 32`) and rejection of excessive jumps.
8. Tampered records do not advance or corrupt receiver chain state.
9. Fresh session generation and cross-session isolation (`SESSION_MISMATCH`).
10. Cross-conversation membership authorization enforcement (HTTP 403 for unauthorized users).
11. Verifiable absence of plaintext payloads and private keys from SQLite storage and logs.
12. 0 false alerts on benign baselines and correct detection of all 4 suspicious fixtures.
13. Deterministic PPS and byte throughput calculations from capture timestamps.
14. Graceful fallback when TShark or capture permissions are missing.
15. Real FIPS 203 ML-KEM-768 hybrid key agreement and Bob Bot round-trip execution.

---

## How to Run Alice and Bob

You can present and test the application in two ways:

### Mode 1: Unified In-App Dual View (Recommended for Classrooms)
Navigate to `http://localhost:3000` and click the **Chat & Endpoints** tab. Both Alice and Bob are rendered side-by-side with separate internal cryptographic states.

### Mode 2: Multi-Window / Multi-Tab Isolated Clients
Open two separate browser windows:
- **Alice Window:** `http://localhost:3000/?role=alice`
- **Bob Window:** `http://localhost:3000/?role=bob`

Each window operates in isolated memory. Messages sent from Alice are relayed through the SQLite backend and delivered to Bob via the Relay API and browser `BroadcastChannel`.

---

## Detailed View & Function Walkthrough

### 1. Overview Dashboard
- **Relay Status:** Real-time SQLite WAL connection and session identification.
- **Safety Fingerprint Display:** 30-character human-comparable verification fingerprint.
- **Measured Metrics Strip:**
  - Encryption mode and epoch size.
  - Capture source and network interface.
  - Total sent vs. verified messages.
  - Network volume (incoming vs. outgoing).
  - Packet throughput (packets/sec and bytes/sec).
  - Active heuristic alerts.
  - Measured microsecond encryption/decryption execution times (`performance.now()`).
  - Directional ratchet positions (`A2B E0:M0` / `B2A E0:M0`).
- **Overhead Analysis:** Compares raw plaintext payload against raw AEAD overhead (28 bytes: 12B nonce + 16B GCM tag), serialized JSON envelope size, and total loopback wire bytes (3 packets: HTTP POST + HTTP 200 OK + TCP ACK).
- **Application Event Log:** Real-time operational audit log.

### 2. Chat & Endpoints
- **Identity & Fingerprint Banner:** Out-of-band identity check to protect against malicious relay key substitution.
- **Alice Endpoint:**
  - View sending and receiving ratchet counters.
  - View conversation history with verification badges.
  - Inspect local-only ratchet key evolution log (displays SHA-256 fingerprints of derived message keys).
  - Send custom messages or trigger quick Bob Bot commands (`hello`, `time`, `help`, `echo <text>`).
- **Bob Endpoint:**
  - View Bob's independent receiving/sending counters.
  - Toggle Bob Bot auto-responder on or off.
  - Receive, authenticate, and decrypt messages.
  - Send manual replies back to Alice.

### 3. Relay Inspector
- **Untrusted Storage View:** Browse all envelopes stored in SQLite (`relay_envelopes`).
- **Zero-Knowledge Guarantee:** Demonstrates that only ciphertext hex, auth tags, nonces, and public routing headers are stored.
- **Detailed Envelope Anatomy:**
  1. *Transmitted Authenticated Header Fields:* Public metadata (`sessionId`, `sender`, `recipient`, `direction`, `epoch`, `msgNum`, `nonceHex`).
  2. *Canonical Serialized AAD Bytes:* Deterministic string authenticated by AES-256-GCM.
  3. *Ciphertext & Tag Breakdown:* Explains the WebCrypto 16-byte tag split.
  4. *Receiver-Derived Values:* Explains values calculated exclusively on the endpoints that never reach the relay.
- **Controlled Tamper Buttons:** Inject one-shot bit-flips, header alterations, or replay attacks directly from the relay.

### 4. Packet Dashboard (with Recharts)
- **Data Source Indicator:** Distinguishes between `RECORDED_PCAP_TRACE`, `SYNTHETIC_FIXTURE`, and `LIVE_CAPTURE_WORKER`.
- **Direction Perspective Selector:** Analyze metrics relative to Alice (`:54110`), Bob (`:54120`), or Relay (`:3000`).
- **Interactive Visualizations:**
  1. *Incoming vs. Outgoing Bytes Chart:* Bar chart of traffic across time buckets.
  2. *Packets Per Second (PPS) Chart:* Rate distribution.
  3. *Recharts Protocol Distribution Pie Chart:* Interactive, color-coded proportional breakdown of captured traffic (`TCP`, `HTTP`, `DNS`, `ARP`, `UDP`, `TLS`) with hover tooltips and legend.
- **Configurable Heuristic Thresholds:** Live form to tune window durations, port counts, SYN ratios, entropy thresholds, and alert cooldowns.
- **Heuristic Evidence Panel:** Shows flagged alerts, observed vs. threshold values, evidence summaries, and benign real-world explanations.
- **Filterable Packet Table:** Filter packets by protocol, IP/MAC/DNS, port, or sliding time window.

### 5. Experiments, Demo Script & Viva Guide
- **Interactive Security Experiments Deck:** 8 one-click buttons with a live verification log.
- **5-Minute Classroom Presentation Script:** Step-by-step timed presentation guide.
- **Opening Isolated Clients Guide:** Multi-window connection guide.
- **Viva Voce Preparation Guide:** 7 detailed technical answers to defense questions (AEAD vs. unauthenticated ciphers, replay protection, key ratcheting, post-compromise security, atomic state commits, TLS vs. E2EE, and anomaly heuristics).
- **Report-to-Implementation Checklist:** Verification matrix of all security requirements.
- **Downloadable Local Python Kit:** View and download standalone local backend scripts.

---

## Interactive Security Experiments

Located in the **Experiments & Docs** tab:

1. **Send Normal Message:** Encrypts, relays, and decrypts a verified payload.
2. **Tamper With Next Ciphertext (1-Bit Flip):** Flips a bit in the ciphertext on the relay. Bob rejects it with `AUTH_FAILED`, outputs no plaintext, and preserves his receive ratchet.
3. **Modify Next Authenticated Header:** Alters the header nonce in transit. Bob's AES-256-GCM verification fails because the canonical AAD bytes do not match.
4. **Replay Last Delivered Record:** Resends a previously accepted envelope. Bob detects the duplicate `(epoch, msgNum)` and rejects it with `REPLAY_DETECTED`.
5. **Send Short Sequence (5 Msgs):** Sends identical plaintexts 5 times. Demonstrates changing message keys, nonces, and an automatic Epoch transition.
6. **Load Recorded Detection Scenario:** Replaces or appends synthetic detection scenarios into the monitor.
7. **Test Mallory Access Denial (403):** Proves the relay denies access to unauthorized users.
8. **Reset Full Demonstration:** Reinitializes all keys, resets session IDs, and clears message tables.

---

## Detection Rules & Heuristics

PacketGuard evaluates network traffic metadata using 4 classroom detection heuristics:

| Rule Name | Heuristic Description | Default Threshold | Benign Cause Explanation |
| :--- | :--- | :--- | :--- |
| **Possible Port Scan** | Excessive distinct destination ports probed from one source to a destination within a sliding window. | $\ge 20$ distinct ports in $10\text{s}$ | Microservice service discovery, parallel health checks, P2P NAT traversal. |
| **Possible SYN Flood** | High rate of TCP SYN packets with a low ratio of completed 3-way handshakes. Correlates full 4-tuples (`SYN` $\to$ `SYN,ACK` $\to$ `ACK`). | $\ge 25$ SYNs in $10\text{s}$ & $\le 25\%$ completed | Server dropping SYN-ACK responses under sudden load, backend unreachability. |
| **Possible ARP Mapping Conflict** | Single IPv4 address announced by multiple distinct hardware MAC addresses within a time window. | $\ge 2$ distinct MACs for 1 IP in $60\text{s}$ | VRRP/HSRP gateway failover, NIC teaming/bonding, VM live migration. |
| **Suspicious DNS Activity** | Subdomain queries featuring excessive label length, high Shannon entropy, or anomalous query rates. | Length $\ge 32$, Entropy $\ge 3.8\text{ bits}$, Rate $\ge 20/10\text{s}$ | CDN hostnames (CloudFront, Akamai), anti-spam SPF/DKIM lookups, antivirus telemetry. |

All rules enforce duplicate alert cooldowns (default: 15 seconds) to prevent alert storms.

---

## Local Python Kit & Standalone Capture Worker

When running the application locally on your laptop, you can capture live network packets using TShark/Pyshark without running the web app with administrator privileges.

### Files in `/local_python_kit/`
- `app.py`: Standalone Python Flask backend providing the same SQLite relay and monitoring API.
- `capture_worker.py`: Non-root live packet capture worker using Pyshark.
- `requirements.txt`: Pinned Python dependencies (`Flask`, `cryptography`, `pyshark`, `requests`, `pytest`).
- `start_local.sh`: Bash startup script.

### Running Live Packet Capture

1. **Install Python Dependencies:**
   ```bash
   pip install -r local_python_kit/requirements.txt
   ```

2. **Grant Non-Root Packet Capture Permissions:**
   - **macOS:** Install Wireshark (`brew install --cask wireshark`), which sets up the `access_bpf` launch daemon (`ChmodBPF`) so standard users can sniff `lo0` and `en0`.
   - **Linux (Ubuntu/Debian):**
     ```bash
     sudo apt update && sudo apt install -y tshark wireshark-common
     sudo dpkg-reconfigure wireshark-common
     sudo usermod -aG wireshark $USER
     sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap
     ```
   - **Windows:** Install Wireshark with **Npcap** and enable *"Support loopback traffic"*.

3. **Start the Capture Worker:**
   ```bash
   python3 local_python_kit/capture_worker.py --interface lo0 --api-url http://localhost:3000
   ```

The worker captures metadata on a bounded queue (capacity 2048 packets) outside the web request thread and streams metadata batches to `/api/monitor/ingest-packets`.

---

## API Endpoints Reference

### Authentication & Sessions
- `POST /api/auth/login`: Authenticate users via PBKDF2-HMAC-SHA-256.
- `GET /api/state`: Retrieve current relay envelopes, packet metadata, alerts, and capture status.

### Relay Operations
- `POST /api/relay/handshake`: Store public session handshake parameters.
- `POST /api/relay/send`: Relay an encrypted envelope (applies armed tamper actions if configured).
- `GET /api/relay/envelopes/:conversationId`: Fetch envelopes for an authorized conversation (enforces membership).
- `POST /api/relay/delivery-status`: Update envelope delivery status (`DELIVERED_VERIFIED`, `REJECTED_AUTH_FAILED`, `REJECTED_REPLAY`).

### PacketGuard & Monitoring
- `POST /api/monitor/scenario`: Load recorded or synthetic packet scenarios (`BENIGN_BASELINE_ALL`, `SUSPICIOUS_PORT_SCAN`, `SUSPICIOUS_SYN_FLOOD`, `SUSPICIOUS_ARP_CONFLICT`, `SUSPICIOUS_DNS_TUNNELING`, `COMBINED_CLASSROOM_DEMO`).
- `POST /api/monitor/rules`: Update detection thresholds and re-evaluate packets.
- `POST /api/monitor/ingest-packets`: Ingest packet metadata from live capture workers.

### Local Kit & Demo Controls
- `POST /api/demo/settings`: Configure local demo controls, tamper actions, and plaintext demo authorization.
- `POST /api/demo/reset`: Clear all session state and reset SQLite tables.
- `GET /api/local-kit/files`: Download standalone Python kit files.

---

## Troubleshooting & FAQ

**Q: Can the relay server read chat messages in encrypted mode?**  
*A:* No. The relay server only stores and routes serialized envelopes (`ciphertextHex`, `authTagHex`, `nonceHex`, and routing headers). It possesses no private keys or message keys. Test #11 in `src/tests/arxPacketGuard.test.ts` audits raw SQLite storage and logs to verify that plaintext strings never appear.

**Q: Why does the app include a Local Plaintext Baseline mode?**  
*A:* For classroom contrast. In plaintext mode, students can observe the difference between transmitting unencrypted data versus authenticated ciphertext. Plaintext mode is gated behind an explicit setting and displays a prominent warning banner.

**Q: Does AES-256-GCM prevent replay attacks?**  
*A:* No. AES-256-GCM guarantees confidentiality and integrity, but a replayed valid packet has a mathematically valid tag. Replay defense is handled by the receiver's stateful tracking of seen `(epoch, msgNum)` pairs and its receiving watermark.

**Q: Why are alerts labeled "Possible" or "Suspicious"?**  
*A:* Metadata heuristics identify statistical anomalies, not cryptographic proof of malicious behavior. Legitimate events like CDN edge queries or VRRP router failover can produce similar metadata patterns.
