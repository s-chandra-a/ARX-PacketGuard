import { describe, expect, it } from 'vitest';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import {
  decryptEndpointMessage,
  encryptEndpointMessage,
  establishSessionPair,
  generateIdentityKeyBundle,
  getEnvelopeForRetry,
  tamperAuthenticatedHeader,
  tamperAuthTag,
  tamperCiphertextBitFlip,
} from '../crypto/arxCrypto.ts';
import { processEnvelopeAtBobBotEndpoint } from '../crypto/bobBot.ts';
import {
  buildClassroomScenarioPackets,
  computeTrafficMetrics,
  DEFAULT_RULE_CONFIG,
  evaluatePacketGuardRules,
  type PacketMetadataRecord,
} from '../monitor/packetGuardEngine.ts';
import { ArxRelayStore } from '../server/relayStore.ts';

describe('ARX-PacketGuard Acceptance Test Suite (15 Criteria)', () => {
  // 1. Encrypt/decrypt round trip, including Unicode
  it('1. performs encrypt/decrypt round trip accurately, including multi-script Unicode', async () => {
    const aliceId = generateIdentityKeyBundle('alice');
    const bobId = generateIdentityKeyBundle('bob');
    const { aliceState, bobState } = establishSessionPair(aliceId, bobId, {
      mode: 'CLASSICAL_X25519',
      epochSize: 5,
    });

    const unicodeMessage = 'Hello Bob! こんにちは 🔐 Ελληνικά — Café & Math ∑(x²)';
    const enc = await encryptEndpointMessage(aliceState, unicodeMessage);
    const dec = await decryptEndpointMessage(bobState, enc.envelope);

    expect(dec.success).toBe(true);
    expect(dec.plaintext).toBe(unicodeMessage);
    expect(enc.envelope.ciphertextHex).not.toBe(bytesToHex(utf8ToBytes(unicodeMessage)));
  });

  // 2. Repeated plaintext producing distinct message key/nonce pairs
  it('2. derives distinct message keys, nonces, and ciphertexts for repeated identical plaintext', async () => {
    const aliceId = generateIdentityKeyBundle('alice');
    const bobId = generateIdentityKeyBundle('bob');
    let { aliceState, bobState } = establishSessionPair(aliceId, bobId, {
      mode: 'CLASSICAL_X25519',
      epochSize: 5,
    });

    const samePlaintext = 'Transfer $500 to Account #1024';
    const seenKeyFingerprints = new Set<string>();
    const seenNonces = new Set<string>();
    const seenCiphertexts = new Set<string>();

    for (let i = 0; i < 4; i++) {
      const enc = await encryptEndpointMessage(aliceState, samePlaintext);
      aliceState = enc.updatedState;
      seenKeyFingerprints.add(enc.localKeyFingerprint);
      seenNonces.add(enc.envelope.header.nonceHex);
      seenCiphertexts.add(enc.envelope.ciphertextHex);

      const dec = await decryptEndpointMessage(bobState, enc.envelope);
      expect(dec.success).toBe(true);
      expect(dec.plaintext).toBe(samePlaintext);
      bobState = dec.updatedState;
    }

    expect(seenKeyFingerprints.size).toBe(4);
    expect(seenNonces.size).toBe(4);
    expect(seenCiphertexts.size).toBe(4);

    // Also verify safe retry returns cached envelope without re-encrypting
    const retryEnv = getEnvelopeForRetry(aliceState, 0, 1);
    expect(retryEnv).toBeDefined();
    expect(retryEnv?.header.msgNum).toBe(1);
  });

  // 3. Separate keys/chains for both directions
  it('3. enforces domain-separated sending chains for A2B (Alice->Bob) and B2A (Bob->Alice)', async () => {
    const aliceId = generateIdentityKeyBundle('alice');
    const bobId = generateIdentityKeyBundle('bob');
    const { aliceState, bobState } = establishSessionPair(aliceId, bobId, {
      mode: 'CLASSICAL_X25519',
      epochSize: 5,
    });

    expect(aliceState.sendChainKeyHex).not.toBe(bobState.sendChainKeyHex);
    expect(aliceState.sendChainKeyHex).toBe(bobState.recvChainKeyHex);
    expect(bobState.sendChainKeyHex).toBe(aliceState.recvChainKeyHex);

    const encA2B = await encryptEndpointMessage(aliceState, 'Ping from Alice');
    const encB2A = await encryptEndpointMessage(bobState, 'Ping from Alice');

    // Even at (epoch=0, msgNum=0) with identical plaintext, A2B and B2A produce distinct keys & nonces
    expect(encA2B.localKeyFingerprint).not.toBe(encB2A.localKeyFingerprint);
    expect(encA2B.envelope.header.nonceHex).not.toBe(encB2A.envelope.header.nonceHex);
  });

  // 4. Ciphertext, tag, and header tampering rejection
  it('4. rejects ciphertext bit-flip, authentication tag corruption, and authenticated header modification', async () => {
    const aliceId = generateIdentityKeyBundle('alice');
    const bobId = generateIdentityKeyBundle('bob');
    const { aliceState, bobState } = establishSessionPair(aliceId, bobId, {
      mode: 'CLASSICAL_X25519',
      epochSize: 5,
    });

    const enc = await encryptEndpointMessage(aliceState, 'Authentic grade report: A+');

    const badCipher = tamperCiphertextBitFlip(enc.envelope);
    const resCipher = await decryptEndpointMessage(bobState, badCipher);
    expect(resCipher.success).toBe(false);
    expect(resCipher.errorType).toBe('AUTH_FAILED');
    expect(resCipher.plaintext).toBeUndefined();

    const badTag = tamperAuthTag(enc.envelope);
    const resTag = await decryptEndpointMessage(bobState, badTag);
    expect(resTag.success).toBe(false);
    expect(resTag.errorType).toBe('AUTH_FAILED');

    const badHeader = tamperAuthenticatedHeader(enc.envelope);
    const resHeader = await decryptEndpointMessage(bobState, badHeader);
    expect(resHeader.success).toBe(false);
    expect(resHeader.errorType).toBe('AUTH_FAILED');
  });

  // 5. Replay rejection
  it('5. rejects replayed envelopes and distinguishes REPLAY_DETECTED from AUTH_FAILED', async () => {
    const aliceId = generateIdentityKeyBundle('alice');
    const bobId = generateIdentityKeyBundle('bob');
    const { aliceState, bobState } = establishSessionPair(aliceId, bobId, {
      mode: 'CLASSICAL_X25519',
      epochSize: 5,
    });

    const enc = await encryptEndpointMessage(aliceState, 'One-time authorization token');
    const firstDec = await decryptEndpointMessage(bobState, enc.envelope);
    expect(firstDec.success).toBe(true);

    // Replay the exact same valid envelope against the updated receiver state
    const replayDec = await decryptEndpointMessage(firstDec.updatedState, enc.envelope);
    expect(replayDec.success).toBe(false);
    expect(replayDec.errorType).toBe('REPLAY_DETECTED');
  });

  // 6. Epoch transitions
  it('6. transitions cleanly across multiple epochs at configured epochSize boundary', async () => {
    const aliceId = generateIdentityKeyBundle('alice');
    const bobId = generateIdentityKeyBundle('bob');
    let { aliceState, bobState } = establishSessionPair(aliceId, bobId, {
      mode: 'CLASSICAL_X25519',
      epochSize: 3, // Transition every 3 messages
    });

    const observedEpochs: number[] = [];
    const observedMsgNums: number[] = [];

    for (let i = 0; i < 7; i++) {
      const enc = await encryptEndpointMessage(aliceState, `Msg #${i}`);
      aliceState = enc.updatedState;
      observedEpochs.push(enc.envelope.header.epoch);
      observedMsgNums.push(enc.envelope.header.msgNum);

      const dec = await decryptEndpointMessage(bobState, enc.envelope);
      expect(dec.success).toBe(true);
      expect(dec.plaintext).toBe(`Msg #${i}`);
      bobState = dec.updatedState;
    }

    expect(observedEpochs).toEqual([0, 0, 0, 1, 1, 1, 2]);
    expect(observedMsgNums).toEqual([0, 1, 2, 0, 1, 2, 0]);
  });

  // 7. Correct out-of-order policy
  it('7. handles out-of-order messages via bounded skipped-key cache and rejects jumps exceeding MAX_SKIP', async () => {
    const aliceId = generateIdentityKeyBundle('alice');
    const bobId = generateIdentityKeyBundle('bob');
    let { aliceState, bobState } = establishSessionPair(aliceId, bobId, {
      mode: 'CLASSICAL_X25519',
      epochSize: 5,
    });

    const e0 = await encryptEndpointMessage(aliceState, 'Message 0');
    aliceState = e0.updatedState;
    const e1 = await encryptEndpointMessage(aliceState, 'Message 1');
    aliceState = e1.updatedState;
    const e2 = await encryptEndpointMessage(aliceState, 'Message 2');
    aliceState = e2.updatedState;

    // Deliver Message 2 FIRST (skipping 0 and 1)
    const d2 = await decryptEndpointMessage(bobState, e2.envelope);
    expect(d2.success).toBe(true);
    expect(d2.plaintext).toBe('Message 2');
    bobState = d2.updatedState;

    // Deliver skipped Message 0 and Message 1 out of order
    const d0 = await decryptEndpointMessage(bobState, e0.envelope);
    expect(d0.success).toBe(true);
    expect(d0.plaintext).toBe('Message 0');
    bobState = d0.updatedState;

    const d1 = await decryptEndpointMessage(bobState, e1.envelope);
    expect(d1.success).toBe(true);
    expect(d1.plaintext).toBe('Message 1');
    bobState = d1.updatedState;

    // Replaying skipped Message 0 again must be rejected as REPLAY_DETECTED
    const replay0 = await decryptEndpointMessage(bobState, e0.envelope);
    expect(replay0.success).toBe(false);
    expect(replay0.errorType).toBe('REPLAY_DETECTED');

    // Jumping beyond MAX_SKIP_KEYS (32) must be rejected with OUT_OF_ORDER_LIMIT
    const farEnvelope = {
      ...e2.envelope,
      header: {
        ...e2.envelope.header,
        epoch: 10,
        msgNum: 0,
      },
    };
    const farRes = await decryptEndpointMessage(bobState, farEnvelope);
    expect(farRes.success).toBe(false);
    expect(farRes.errorType).toBe('OUT_OF_ORDER_LIMIT');
  });

  // 8. Rejected messages not corrupting receive state
  it('8. preserves receiver chain state when tampered records are rejected so subsequent messages succeed', async () => {
    const aliceId = generateIdentityKeyBundle('alice');
    const bobId = generateIdentityKeyBundle('bob');
    let { aliceState, bobState } = establishSessionPair(aliceId, bobId, {
      mode: 'CLASSICAL_X25519',
      epochSize: 5,
    });

    const msg0 = await encryptEndpointMessage(aliceState, 'Valid Message 0');
    aliceState = msg0.updatedState;

    // Inject tampered versions of msg0 before delivering valid msg0
    const tampered1 = await decryptEndpointMessage(bobState, tamperCiphertextBitFlip(msg0.envelope));
    expect(tampered1.success).toBe(false);
    expect(tampered1.errorType).toBe('AUTH_FAILED');
    bobState = tampered1.updatedState;

    const tampered2 = await decryptEndpointMessage(bobState, tamperAuthenticatedHeader(msg0.envelope));
    expect(tampered2.success).toBe(false);
    expect(tampered2.errorType).toBe('AUTH_FAILED');
    bobState = tampered2.updatedState;

    // Now deliver valid msg0 and msg1 -> both must succeed!
    const valid0 = await decryptEndpointMessage(bobState, msg0.envelope);
    expect(valid0.success).toBe(true);
    expect(valid0.plaintext).toBe('Valid Message 0');
    bobState = valid0.updatedState;

    const msg1 = await encryptEndpointMessage(aliceState, 'Valid Message 1');
    const valid1 = await decryptEndpointMessage(bobState, msg1.envelope);
    expect(valid1.success).toBe(true);
    expect(valid1.plaintext).toBe('Valid Message 1');
  });

  // 9. Reset/restart creating a fresh session
  it('9. creates a fresh session with distinct sessionId, keys, and safety fingerprint on reset', async () => {
    const aliceId1 = generateIdentityKeyBundle('alice');
    const bobId1 = generateIdentityKeyBundle('bob');
    const session1 = establishSessionPair(aliceId1, bobId1, { mode: 'CLASSICAL_X25519' });

    const aliceId2 = generateIdentityKeyBundle('alice');
    const bobId2 = generateIdentityKeyBundle('bob');
    const session2 = establishSessionPair(aliceId2, bobId2, { mode: 'CLASSICAL_X25519' });

    expect(session1.handshake.sessionId).not.toBe(session2.handshake.sessionId);
    expect(session1.aliceState.safetyFingerprint).not.toBe(session2.aliceState.safetyFingerprint);
    expect(session1.aliceState.sendChainKeyHex).not.toBe(session2.aliceState.sendChainKeyHex);

    // Envelope from session 1 is rejected by session 2 with SESSION_MISMATCH
    const enc1 = await encryptEndpointMessage(session1.aliceState, 'Old session message');
    const crossDec = await decryptEndpointMessage(session2.bobState, enc1.envelope);
    expect(crossDec.success).toBe(false);
    expect(crossDec.errorType).toBe('SESSION_MISMATCH');
  });

  // 10. Cross-conversation access denial
  it('10. enforces conversation membership checks on the relay and denies unauthorized users (403)', async () => {
    const store = new ArxRelayStore(':memory:');
    const aliceId = generateIdentityKeyBundle('alice');
    const bobId = generateIdentityKeyBundle('bob');
    const { handshake, aliceState } = establishSessionPair(aliceId, bobId, {
      mode: 'CLASSICAL_X25519',
    });

    // Alice can store handshake and send envelope in conv-alice-bob
    const hsRes = store.storeHandshake('conv-alice-bob', 'alice', handshake);
    expect(hsRes.ok).toBe(true);
    expect(hsRes.status).toBe(200);

    const enc = await encryptEndpointMessage(aliceState, 'Confidential message for Bob');
    const sendRes = store.relayEnvelope('conv-alice-bob', 'alice', enc.envelope);
    expect(sendRes.ok).toBe(true);

    // Bob can fetch envelopes
    const bobRead = store.getConversationEnvelopes('conv-alice-bob', 'bob');
    expect(bobRead.ok).toBe(true);
    expect(bobRead.envelopes?.length).toBe(1);

    // Mallory (valid authenticated user, not in conv-alice-bob) is denied read & write with 403
    const malloryRead = store.getConversationEnvelopes('conv-alice-bob', 'mallory');
    expect(malloryRead.ok).toBe(false);
    expect(malloryRead.status).toBe(403);

    const mallorySend = store.relayEnvelope('conv-alice-bob', 'mallory', enc.envelope);
    expect(mallorySend.ok).toBe(false);
    expect(mallorySend.status).toBe(403);
  });

  // 11. Known test plaintext absent from encrypted relay storage and logs
  it('11. ensures known test plaintext and secret keys are completely absent from SQLite relay storage and logs', async () => {
    const store = new ArxRelayStore(':memory:');
    const aliceId = generateIdentityKeyBundle('alice');
    const bobId = generateIdentityKeyBundle('bob');
    const { handshake, aliceState } = establishSessionPair(aliceId, bobId, {
      mode: 'CLASSICAL_X25519',
    });

    store.storeHandshake('conv-alice-bob', 'alice', handshake);

    const secretMarker = 'CLASSIFIED_NUCLEAR_CODE_884920_DO_NOT_LEAK';
    const secretMarkerHex = bytesToHex(utf8ToBytes(secretMarker));

    const enc = await encryptEndpointMessage(aliceState, secretMarker);
    store.relayEnvelope('conv-alice-bob', 'alice', enc.envelope);

    const rawDump = store.dumpRawRelayStorageForAudit();
    expect(rawDump).not.toContain(secretMarker);
    expect(rawDump).not.toContain(secretMarkerHex);
    expect(rawDump).not.toContain(aliceId.x25519PrivateKeyHex);
    expect(rawDump).not.toContain(aliceState.sendChainKeyHex);
  });

  // 12. Detector behavior for benign and suspicious fixtures
  it('12. triggers zero alerts on benign baseline and accurate alerts on all 4 suspicious fixtures', () => {
    const benignPackets = buildClassroomScenarioPackets('BENIGN_BASELINE_ALL');
    const benignAlerts = evaluatePacketGuardRules(benignPackets, DEFAULT_RULE_CONFIG);
    expect(benignAlerts.length).toBe(0);

    const scanAlerts = evaluatePacketGuardRules(
      buildClassroomScenarioPackets('SUSPICIOUS_PORT_SCAN'),
      DEFAULT_RULE_CONFIG
    );
    expect(scanAlerts.some((a) => a.ruleId === 'POSSIBLE_PORT_SCAN')).toBe(true);

    const synAlerts = evaluatePacketGuardRules(
      buildClassroomScenarioPackets('SUSPICIOUS_SYN_FLOOD'),
      DEFAULT_RULE_CONFIG
    );
    expect(synAlerts.some((a) => a.ruleId === 'POSSIBLE_SYN_FLOOD')).toBe(true);

    const arpAlerts = evaluatePacketGuardRules(
      buildClassroomScenarioPackets('SUSPICIOUS_ARP_CONFLICT'),
      DEFAULT_RULE_CONFIG
    );
    expect(arpAlerts.some((a) => a.ruleId === 'POSSIBLE_ARP_CONFLICT')).toBe(true);

    const dnsAlerts = evaluatePacketGuardRules(
      buildClassroomScenarioPackets('SUSPICIOUS_DNS_TUNNELING'),
      DEFAULT_RULE_CONFIG
    );
    expect(dnsAlerts.some((a) => a.ruleId === 'SUSPICIOUS_DNS_ACTIVITY')).toBe(true);
  });

  // 13. Traffic-rate calculations with controlled timestamps
  it('13. computes accurate packet rate (PPS) and byte rate (B/s) from controlled timestamps', () => {
    const baseTs = 1700000000000;
    const controlledPackets: PacketMetadataRecord[] = [
      {
        packetId: 'p1',
        timestampMs: baseTs,
        sourceType: 'RECORDED_PCAP_TRACE',
        scenarioName: 'Test',
        interfaceName: 'lo0',
        srcIp: '127.0.0.1',
        dstIp: '127.0.0.1',
        srcPort: 54110, // Alice
        dstPort: 3000,
        protocol: 'HTTP',
        capturedBytes: 500,
      },
      {
        packetId: 'p2',
        timestampMs: baseTs + 2000,
        sourceType: 'RECORDED_PCAP_TRACE',
        scenarioName: 'Test',
        interfaceName: 'lo0',
        srcIp: '127.0.0.1',
        dstIp: '127.0.0.1',
        srcPort: 3000,
        dstPort: 54110, // To Alice
        protocol: 'HTTP',
        capturedBytes: 300,
      },
      {
        packetId: 'p3',
        timestampMs: baseTs + 4000, // Total span = 4.0 seconds
        sourceType: 'RECORDED_PCAP_TRACE',
        scenarioName: 'Test',
        interfaceName: 'lo0',
        srcIp: '127.0.0.1',
        dstIp: '127.0.0.1',
        srcPort: 54110,
        dstPort: 3000,
        protocol: 'TCP',
        capturedBytes: 200,
      },
    ];

    const metrics = computeTrafficMetrics(controlledPackets, 'alice');
    expect(metrics.totalPackets).toBe(3);
    expect(metrics.totalCapturedBytes).toBe(1000);
    expect(metrics.outgoingBytesClient).toBe(700);
    expect(metrics.incomingBytesClient).toBe(300);
    expect(metrics.packetsPerSecond).toBe(0.75); // 3 packets / 4 seconds
    expect(metrics.bytesPerSecond).toBe(250);    // 1000 bytes / 4 seconds
  });

  // 14. Missing capture dependency producing a clear fallback
  it('14. produces a graceful, informative fallback when TShark binary is unavailable', () => {
    const store = new ArxRelayStore(':memory:');
    const status = store.probeLiveCaptureEnvironment('/nonexistent/bin/tshark-missing');
    expect(status.tsharkInstalled).toBe(false);
    expect(status.activeCaptureMode).toBe('RECORDED_OR_SYNTHETIC');
    expect(status.fallbackReason.length).toBeGreaterThan(20);
  });

  // 15. Hybrid interoperability (X25519 + ML-KEM-768) & Bob Bot endpoint round-trip
  it('15. establishes hybrid X25519 + NIST FIPS 203 ML-KEM-768 sessions and runs Bob Bot endpoint', async () => {
    const aliceId = generateIdentityKeyBundle('alice');
    const bobId = generateIdentityKeyBundle('bob');
    const { handshake, aliceState, bobState } = establishSessionPair(aliceId, bobId, {
      mode: 'HYBRID_X25519_MLKEM768',
      epochSize: 5,
    });

    // Verify real FIPS 203 ML-KEM-768 ciphertext size (1088 bytes = 2176 hex chars)
    expect(handshake.mlKem768CiphertextHex).toBeDefined();
    expect(handshake.mlKem768CiphertextHex?.length).toBe(1088 * 2);
    expect(aliceState.safetyFingerprint).toBe(bobState.safetyFingerprint);

    // Alice sends "echo Hybrid PQC Works!" to Bob Bot endpoint
    const aliceEnc = await encryptEndpointMessage(aliceState, 'echo Hybrid PQC Works!');
    const botOutcome = await processEnvelopeAtBobBotEndpoint(bobState, aliceEnc.envelope);

    expect(botOutcome.inboundDecrypt.success).toBe(true);
    expect(botOutcome.botReplyPlaintext).toBe('[Bob Bot Echo]: Hybrid PQC Works!');
    expect(botOutcome.outboundEncrypt).toBeDefined();

    // Alice decrypts Bob Bot's encrypted reply
    const aliceDec = await decryptEndpointMessage(
      aliceEnc.updatedState,
      botOutcome.outboundEncrypt!.envelope
    );
    expect(aliceDec.success).toBe(true);
    expect(aliceDec.plaintext).toBe('[Bob Bot Echo]: Hybrid PQC Works!');
  });
});
