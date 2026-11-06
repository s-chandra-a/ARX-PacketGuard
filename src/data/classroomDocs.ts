export interface VivaQuestion {
  topic: string;
  question: string;
  conciseAnswer: string;
  technicalDetail: string;
}

export interface ChecklistItem {
  category: string;
  requirement: string;
  status: 'VERIFIED' | 'DOCUMENTED_CORRECTION';
  implementationNotes: string;
}

export const FIVE_MINUTE_DEMO_SCRIPT = [
  {
    minute: '0:00 – 1:00',
    title: 'Stage 1: Session Establishment & Safety Fingerprint Verification',
    actions: [
      'Open the Chat & Endpoints view (or open two browser windows side by side with ?role=alice and ?role=bob).',
      'Select "Hybrid (X25519 + ML-KEM-768)" or "Classical (X25519)" and set Epoch Size = 5 messages.',
      'Click "Establish Fresh Session". Point out that Alice and Bob compute identical 30-character Safety Fingerprints locally while the Relay only receives public keys and the 1088-byte ML-KEM ciphertext.',
    ],
  },
  {
    minute: '1:00 – 2:15',
    title: 'Stage 2: End-to-End Ratcheting, Key Evolution & Ciphertext-Only Relay',
    actions: [
      'Send the exact same message ("Transfer $500") three times from Alice to Bob, or click "Send 5-Message Ratchet Sequence" in Security Experiments.',
      'Open the Relay Inspector view: show that every transmitted envelope has a distinct 96-bit Nonce, distinct AES-256-GCM Ciphertext, and distinct 128-bit Auth Tag—and zero plaintext exists in SQLite.',
      'Cross the 5-message boundary to demonstrate Epoch 0 -> Epoch 1 transition and explain why deterministic epoch ratcheting separates keys forward without adding fresh entropy.',
    ],
  },
  {
    minute: '2:15 – 3:30',
    title: 'Stage 3: Active Tampering & Replay Rejection Experiments',
    actions: [
      'In Security Experiments, click "Tamper Next Ciphertext (1-Bit Flip)" or "Modify Next Authenticated Header".',
      'Observe that Bob immediately rejects the record with AES-256-GCM Authentication Failure, displays zero corrupted plaintext, and does NOT advance his receiving chain.',
      'Send a normal message right after to prove Bob’s receiving state was not corrupted by the rejected packet.',
      'Click "Replay Last Delivered Record" and show that Bob rejects it with REPLAY_DETECTED (distinct from AUTH_FAILED).',
    ],
  },
  {
    minute: '3:30 – 5:00',
    title: 'Stage 4: PacketGuard Metadata Inspection & Heuristic Detection Rules',
    actions: [
      'Switch to PacketGuard Dashboard. Show that 1 application message produced 3 loopback packets (HTTP POST PSH,ACK + HTTP 200 OK + TCP ACK) and compare raw 28-byte crypto overhead (12B nonce + 16B tag) against JSON/HTTP/TCP framing.',
      'Load "Benign Lab Baseline" (0 alerts) followed by "Combined Classroom Demo" (Port Scan, Uncompleted SYN Burst with flow correlation, ARP MAC Conflict, and High-Entropy DNS).',
      'Adjust a rule threshold live (e.g., Port Scan threshold) to show real-time re-evaluation and discuss benign false-positive explanations.',
    ],
  },
];

export const VIVA_PREPARATION_QA: VivaQuestion[] = [
  {
    topic: 'Confidentiality vs. Integrity',
    question: 'Why do we use AES-256-GCM instead of unauthenticated AES-CBC or AES-CTR?',
    conciseAnswer:
      'AES-256-GCM is an AEAD (Authenticated Encryption with Associated Data) cipher that provides both confidentiality and integrity via a 128-bit authentication tag.',
    technicalDetail:
      'Without authentication, an active relay or network attacker could flip bits in the ciphertext or modify header fields (epoch, message number, direction) without detection. AES-256-GCM authenticates both the ciphertext and the canonical UTF-8 serialized header (AAD) before a single byte of plaintext is released.',
  },
  {
    topic: 'Replay Protection vs. AEAD',
    question: 'If AES-256-GCM authenticates every record, why doesn’t AES-GCM automatically prevent replay attacks?',
    conciseAnswer:
      'A replayed envelope is bit-for-bit identical to the original valid envelope, so its AES-GCM authentication tag is still mathematically valid under the same key and nonce.',
    technicalDetail:
      'Replay defense requires stateful endpoint tracking. ARX tracks seen (epoch, msgNum) pairs and advances a one-way receiving ratchet watermark so any duplicate or stale record is rejected with REPLAY_DETECTED before decryption.',
  },
  {
    topic: 'Per-Message Ratcheting & Key Evolution',
    question: 'Does seeing different ciphertext for the same plaintext prove that message keys are ratcheting?',
    conciseAnswer:
      'No—even a static key with a random nonce produces different ciphertext. True ratcheting means the 256-bit message key itself evolves one-way after every message.',
    technicalDetail:
      'ARX runs an HKDF-SHA-256 ratchet step on the directional chain key (chainKey_n -> chainKey_{n+1}, messageKey_n, nonce_n) bound to protocolVersion, sessionId, sender, recipient, direction, epoch, and msgNum. In the endpoint teaching panel, we verify that the local SHA-256 fingerprint of each derived messageKey is unique.',
  },
  {
    topic: 'Epochs & Post-Compromise Security',
    question: 'Does our deterministic Epoch transition (every N messages) provide Signal-level post-compromise security (PCS)?',
    conciseAnswer:
      'No. Deterministic HKDF epoch transitions provide forward key separation when old secrets are discarded, but do not add fresh secret entropy.',
    technicalDetail:
      'If an attacker compromises the current epoch secret, they can compute future deterministic epoch secrets unless a fresh Diffie-Hellman or ML-KEM encapsulation exchange injects new randomness. We explicitly document this distinction.',
  },
  {
    topic: 'Safe Receiver State Advancement',
    question: 'What happens if an attacker injects a forged packet with msgNum = 5? Does it desynchronize Bob’s ratchet?',
    conciseAnswer:
      'No. Receiver state and skipped-key caches are advanced tentatively in memory and committed ONLY after AES-256-GCM tag verification succeeds.',
    technicalDetail:
      'If authentication fails, the tentative chain advancement is discarded and Bob’s recvChainKey, recvEpoch, and recvMsgNum remain untouched, allowing the true message #5 to decrypt normally when it arrives.',
  },
  {
    topic: 'Metadata Visibility & TLS vs. End-to-End Encryption',
    question: 'What can PacketGuard still observe when ARX encryption is enabled, and how does HTTPS/TLS relate to ARX?',
    conciseAnswer:
      'PacketGuard cannot read message content, but it can still observe IP addresses, ports, packet sizes, inter-arrival timing, and message frequency.',
    technicalDetail:
      'Transport-layer TLS (HTTPS) encrypts the link between client and relay (hiding even our local plaintext baseline from passive wire sniffers), whereas ARX end-to-end encryption protects content from the relay server itself.',
  },
  {
    topic: 'Heuristic Anomaly Detection',
    question: 'Why does PacketGuard label alerts as "Possible" or "Suspicious" and correlate TCP 4-tuples for SYN floods?',
    conciseAnswer:
      'Metadata rules are statistical heuristics, not cryptographic proof of malicious intent, and naive packet counting produces false positives.',
    technicalDetail:
      'Counting arbitrary ACK packets on a busy server would mask a SYN flood. PacketGuard correlates 4-tuple flows (SYN -> SYN,ACK -> ACK) to measure true handshake completion ratios, and documents benign causes (CDN hostnames for DNS entropy, VRRP failover for ARP changes).',
  },
];

export const REPORT_TO_IMPLEMENTATION_CHECKLIST: ChecklistItem[] = [
  {
    category: 'Cryptography & Ratchet',
    requirement: 'X25519 + HKDF-SHA-256 + AES-256-GCM with domain-separated A2B/B2A chains',
    status: 'VERIFIED',
    implementationNotes:
      'Implemented in src/crypto/arxCrypto.ts using @noble/curves, @noble/hashes, and WebCrypto AES-256-GCM with canonical AAD header binding.',
  },
  {
    category: 'Post-Quantum Hybrid Mode',
    requirement: 'X25519 + ML-KEM-768 hybrid session establishment with real KEM encap/decap',
    status: 'VERIFIED',
    implementationNotes:
      'Implemented using audited @noble/post-quantum FIPS 203 ml_kem768 (1184B public key, 1088B ciphertext, 32B shared secret combined with X25519 via context-bound HKDF).',
  },
  {
    category: 'State & Replay Safety',
    requirement: 'Commit receive state only after authentication; bounded out-of-order skipped-key cache',
    status: 'DOCUMENTED_CORRECTION',
    implementationNotes:
      'Corrected common report pitfall where naive receivers increment msgNum before tag verification. Implemented tentative KDF evaluation + MAX_SKIP=32 cache committed only post-GCM verification.',
  },
  {
    category: 'Overhead Measurement',
    requirement: 'Distinguish raw cryptographic overhead from JSON/hex serialization and TCP/IP transport overhead',
    status: 'DOCUMENTED_CORRECTION',
    implementationNotes:
      'Rather than hardcoding an unverified 40-byte constant, the UI measures and displays exact raw crypto primitives (12B nonce + 16B GCM tag = 28B), canonical AAD header bytes, JSON envelope bytes, and captured TCP/HTTP packet bytes.',
  },
  {
    category: 'PacketGuard Heuristics',
    requirement: 'Port scan, flow-correlated SYN flood, ARP conflict, and DNS entropy/rate rules with cooldown',
    status: 'VERIFIED',
    implementationNotes:
      'Implemented in src/monitor/packetGuardEngine.ts with 4-tuple TCP handshake correlation, Shannon entropy calculation, and per-(rule, src, dst) cooldown windows.',
  },
  {
    category: 'Capture Architecture',
    requirement: 'Separate Recorded PCAP trace, Synthetic Fixtures, and Local Non-Root Pyshark Worker',
    status: 'VERIFIED',
    implementationNotes:
      'Hosted preview never fakes live NIC capture; provides labeled Recorded/Synthetic datasets plus downloadable local_python_kit/capture_worker.py & app.py.',
  },
];
