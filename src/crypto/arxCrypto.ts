import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from '@noble/hashes/utils.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';

export type EncryptionMode =
  | 'CLASSICAL_X25519'
  | 'HYBRID_X25519_MLKEM768'
  | 'LOCAL_PLAINTEXT_BASELINE';

export type Direction = 'A2B' | 'B2A';
export type ParticipantId = 'alice' | 'bob';

export interface IdentityKeyBundle {
  participant: ParticipantId;
  x25519PrivateKeyHex: string;
  x25519PublicKeyHex: string;
  mlKem768SecretKeyHex: string;
  mlKem768PublicKeyHex: string;
  createdAt: number;
}

export interface PublicPreKeyBundle {
  participant: ParticipantId;
  x25519PublicKeyHex: string;
  mlKem768PublicKeyHex: string;
}

export interface SessionInitHandshake {
  sessionId: string;
  mode: EncryptionMode;
  protocolVersion: string;
  epochSize: number;
  initiator: ParticipantId;
  responder: ParticipantId;
  aliceX25519PublicHex: string;
  bobX25519PublicHex: string;
  bobMlKem768PublicHex?: string;
  mlKem768CiphertextHex?: string; // 1088 bytes encapsulated by Alice for Bob in Hybrid mode
  createdAt: number;
}

export interface AuthenticatedHeader {
  protocolVersion: string;
  sessionId: string;
  sender: ParticipantId;
  recipient: ParticipantId;
  direction: Direction;
  epoch: number;
  msgNum: number;
  nonceHex: string; // 12 bytes (96-bit GCM IV)
}

export interface EncryptedEnvelope {
  envelopeId: string;
  header: AuthenticatedHeader;
  mode: EncryptionMode;
  ciphertextHex: string; // Raw AES-GCM ciphertext excluding 16-byte tag (or UTF-8 hex in plaintext mode)
  authTagHex: string;    // 16-byte (128-bit) AES-GCM authentication tag (empty in plaintext mode)
  timestampMs: number;
  // Educational local/inspector metadata (no secret keys ever included)
  plaintextByteLength: number;
  serializedEnvelopeBytes: number;
  cryptoOverheadBytes: number; // 12-byte nonce + 16-byte GCM tag = 28 bytes raw crypto primitives + canonical header
  tamperedFlag?: 'NONE' | 'CIPHERTEXT_BITFLIP' | 'HEADER_MODIFIED' | 'TAG_CORRUPTED';
}

export interface SkippedKeyEntry {
  messageKeyHex: string;
  nonceHex: string;
  keyFingerprint: string;
}

export interface EndpointSessionState {
  owner: ParticipantId;
  peer: ParticipantId;
  sessionId: string;
  mode: EncryptionMode;
  protocolVersion: string;
  epochSize: number;
  safetyFingerprint: string;

  // Sending chain state
  sendDirection: Direction;
  sendEpoch: number;
  sendMsgNum: number;
  sendEpochSecretHex: string;
  sendChainKeyHex: string;

  // Receiving chain state
  recvDirection: Direction;
  recvEpoch: number;
  recvMsgNum: number;
  recvEpochSecretHex: string;
  recvChainKeyHex: string;

  // Replay & out-of-order tracking
  seenMessageKeys: string[]; // "epoch:msgNum"
  skippedKeys: Record<string, SkippedKeyEntry>; // "epoch:msgNum" -> SkippedKeyEntry
  maxSkip: number;

  // Outbox cache for safe retries without re-encrypting under old state
  sentEnvelopesBySeq: Record<string, EncryptedEnvelope>;

  // Local-only educational audit trail (never sent to relay)
  localKeyEvolutionLog: Array<{
    direction: Direction;
    epoch: number;
    msgNum: number;
    nonceHex: string;
    keyFingerprint: string; // Short SHA-256 prefix of messageKey for teaching verification
    timestamp: number;
  }>;
}

export interface EncryptResult {
  envelope: EncryptedEnvelope;
  updatedState: EndpointSessionState;
  executionTimeMs: number;
  localKeyFingerprint: string;
}

export interface DecryptResult {
  success: boolean;
  plaintext?: string;
  errorType?: 'AUTH_FAILED' | 'REPLAY_DETECTED' | 'OUT_OF_ORDER_LIMIT' | 'SESSION_MISMATCH' | 'PLAINTEXT_DISABLED';
  errorMessage?: string;
  updatedState: EndpointSessionState;
  executionTimeMs: number;
  localKeyFingerprint?: string;
}

export const MAX_SKIP_KEYS = 32;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function nowPerf(): number {
  return typeof performance !== 'undefined' ? performance.now() : Date.now();
}

export function getProtocolVersion(mode: EncryptionMode): string {
  switch (mode) {
    case 'CLASSICAL_X25519':
      return 'ARX-1.0-CLASSICAL';
    case 'HYBRID_X25519_MLKEM768':
      return 'ARX-1.0-HYBRID-MLKEM768';
    case 'LOCAL_PLAINTEXT_BASELINE':
      return 'ARX-1.0-PLAINTEXT-DEMO';
  }
}

/**
 * Generates fresh endpoint identity keys (X25519 + NIST FIPS 203 ML-KEM-768).
 */
export function generateIdentityKeyBundle(participant: ParticipantId): IdentityKeyBundle {
  const x25519Keys = x25519.keygen();
  const mlKemKeys = ml_kem768.keygen();
  return {
    participant,
    x25519PrivateKeyHex: bytesToHex(x25519Keys.secretKey),
    x25519PublicKeyHex: bytesToHex(x25519Keys.publicKey),
    mlKem768SecretKeyHex: bytesToHex(mlKemKeys.secretKey),
    mlKem768PublicKeyHex: bytesToHex(mlKemKeys.publicKey),
    createdAt: Date.now(),
  };
}

export function extractPublicPreKeyBundle(bundle: IdentityKeyBundle): PublicPreKeyBundle {
  return {
    participant: bundle.participant,
    x25519PublicKeyHex: bundle.x25519PublicKeyHex,
    mlKem768PublicKeyHex: bundle.mlKem768PublicKeyHex,
  };
}

/**
 * Computes a deterministic, human-comparable safety fingerprint over the session context
 * and public keys so Alice and Bob can detect an active MITM key substitution on the relay.
 */
export function computeSafetyFingerprint(
  sessionId: string,
  aliceX25519PubHex: string,
  bobX25519PubHex: string,
  mode: EncryptionMode,
  bobMlKemPubHex?: string
): string {
  const transcript = [
    'ARX-SAFETY-FP-V1',
    mode,
    sessionId,
    `alice:${aliceX25519PubHex.toLowerCase()}`,
    `bob:${bobX25519PubHex.toLowerCase()}`,
    bobMlKemPubHex ? `mlkem768:${bobMlKemPubHex.toLowerCase()}` : 'mlkem768:none',
  ].join('|');
  const digest = sha256(utf8ToBytes(transcript));
  const hex = bytesToHex(digest).toUpperCase();
  // Format as 6 blocks of 5 hex characters for classroom readability
  return [
    hex.slice(0, 5),
    hex.slice(5, 10),
    hex.slice(10, 15),
    hex.slice(15, 20),
    hex.slice(20, 25),
    hex.slice(25, 30),
  ].join('-');
}

/**
 * Computes a local-only educational fingerprint of a secret message key.
 * Never transmitted to the relay or network monitor.
 */
export function computeLocalKeyFingerprint(messageKeyBytes: Uint8Array): string {
  const digest = sha256(concatBytes(utf8ToBytes('ARX-LOCAL-TEACHING-FP|'), messageKeyBytes));
  return bytesToHex(digest).slice(0, 12);
}

/**
 * Deterministic canonical byte serialization of the Authenticated Header (AAD).
 * Both endpoints authenticate these exact UTF-8 bytes in AES-256-GCM.
 */
export function serializeAuthenticatedHeader(header: AuthenticatedHeader): Uint8Array {
  const canonical = [
    'ARX-AAD-V1',
    `proto=${header.protocolVersion}`,
    `sid=${header.sessionId}`,
    `from=${header.sender}`,
    `to=${header.recipient}`,
    `dir=${header.direction}`,
    `epoch=${header.epoch}`,
    `msg=${header.msgNum}`,
    `nonce=${header.nonceHex.toLowerCase()}`,
  ].join('|');
  return textEncoder.encode(canonical);
}

export function formatCanonicalHeaderString(header: AuthenticatedHeader): string {
  return textDecoder.decode(serializeAuthenticatedHeader(header));
}

/**
 * Derives a directional chain key from an epoch secret, bound to sessionId, protocolVersion, direction, and epoch.
 */
function deriveDirectionalChainKey(
  epochSecretBytes: Uint8Array,
  protocolVersion: string,
  sessionId: string,
  direction: Direction,
  epoch: number
): Uint8Array {
  const salt = sha256(utf8ToBytes(`ARX-CHAIN-SALT|${sessionId}|${epoch}`));
  const info = utf8ToBytes(
    `ARX-DIRECTION-CHAIN|v1|${protocolVersion}|sid=${sessionId}|dir=${direction}|epoch=${epoch}`
  );
  return hkdf(sha256, epochSecretBytes, salt, info, 32);
}

/**
 * Deterministically advances the epoch secret (`epoch -> epoch + 1`) and derives the new directional chain key.
 * Educational note: Deterministic epoch ratcheting provides forward key separation across epochs,
 * but unlike a fresh Diffie-Hellman ratchet, it does not inject new entropy for post-compromise recovery.
 */
function advanceEpochSecret(
  currentEpochSecretBytes: Uint8Array,
  protocolVersion: string,
  sessionId: string,
  direction: Direction,
  nextEpoch: number
): { nextEpochSecretHex: string; nextChainKeyHex: string } {
  const salt = sha256(utf8ToBytes(`ARX-EPOCH-SALT|${sessionId}|${nextEpoch}`));
  const info = utf8ToBytes(
    `ARX-EPOCH-ADVANCE|v1|${protocolVersion}|sid=${sessionId}|dir=${direction}|nextEpoch=${nextEpoch}`
  );
  const nextEpochSecretBytes = hkdf(sha256, currentEpochSecretBytes, salt, info, 32);
  const nextChainKeyBytes = deriveDirectionalChainKey(
    nextEpochSecretBytes,
    protocolVersion,
    sessionId,
    direction,
    nextEpoch
  );
  return {
    nextEpochSecretHex: bytesToHex(nextEpochSecretBytes),
    nextChainKeyHex: bytesToHex(nextChainKeyBytes),
  };
}

/**
 * One-way per-message KDF step:
 * Takes current 32-byte `chainKey` and derives:
 * - `nextChainKey` (32 bytes)
 * - `messageKey` (32 bytes for AES-256-GCM)
 * - `nonce` (12 bytes for AES-256-GCM)
 * Bound to protocolVersion, sessionId, sender, recipient, direction, epoch, and msgNum.
 */
export function kdfRatchetStep(
  chainKeyHex: string,
  protocolVersion: string,
  sessionId: string,
  sender: ParticipantId,
  recipient: ParticipantId,
  direction: Direction,
  epoch: number,
  msgNum: number
): {
  nextChainKeyHex: string;
  messageKeyBytes: Uint8Array;
  messageKeyHex: string;
  nonceBytes: Uint8Array;
  nonceHex: string;
  keyFingerprint: string;
} {
  const chainKeyBytes = hexToBytes(chainKeyHex);
  const salt = sha256(utf8ToBytes(`ARX-MSG-SALT|${sessionId}|${direction}|${epoch}|${msgNum}`));
  const info = utf8ToBytes(
    `ARX-MSG-KDF|v1|proto=${protocolVersion}|sid=${sessionId}|from=${sender}|to=${recipient}|dir=${direction}|epoch=${epoch}|msg=${msgNum}`
  );
  // 32 bytes nextChainKey + 32 bytes messageKey + 12 bytes nonce = 76 bytes
  const okm = hkdf(sha256, chainKeyBytes, salt, info, 76);
  const nextChainKeyBytes = okm.slice(0, 32);
  const messageKeyBytes = okm.slice(32, 64);
  const nonceBytes = okm.slice(64, 76);

  return {
    nextChainKeyHex: bytesToHex(nextChainKeyBytes),
    messageKeyBytes,
    messageKeyHex: bytesToHex(messageKeyBytes),
    nonceBytes,
    nonceHex: bytesToHex(nonceBytes),
    keyFingerprint: computeLocalKeyFingerprint(messageKeyBytes),
  };
}

/**
 * Initiates a new ARX session from Alice (initiator) to Bob (responder), returning the
 * handshake descriptor and both endpoints' independent initial states.
 */
export function establishSessionPair(
  aliceBundle: IdentityKeyBundle,
  bobBundle: IdentityKeyBundle,
  options: {
    mode: EncryptionMode;
    epochSize?: number;
    sessionId?: string;
  }
): {
  handshake: SessionInitHandshake;
  aliceState: EndpointSessionState;
  bobState: EndpointSessionState;
} {
  const epochSize = Math.max(1, options.epochSize ?? 5);
  const randomBytes = new Uint8Array(12);
  globalThis.crypto.getRandomValues(randomBytes);
  const sessionId = options.sessionId || `sid-${bytesToHex(randomBytes)}`;
  const protocolVersion = getProtocolVersion(options.mode);

  const aliceX25519Priv = hexToBytes(aliceBundle.x25519PrivateKeyHex);
  const aliceX25519Pub = hexToBytes(aliceBundle.x25519PublicKeyHex);
  const bobX25519Priv = hexToBytes(bobBundle.x25519PrivateKeyHex);
  const bobX25519Pub = hexToBytes(bobBundle.x25519PublicKeyHex);

  // 1. Classical X25519 ECDH shared secret on both endpoints
  const aliceDhSecret = x25519.getSharedSecret(aliceX25519Priv, bobX25519Pub);
  const bobDhSecret = x25519.getSharedSecret(bobX25519Priv, aliceX25519Pub);

  let mlKemCiphertextHex: string | undefined;
  let aliceCombinedIkm = aliceDhSecret;
  let bobCombinedIkm = bobDhSecret;

  // 2. If Hybrid mode, perform real FIPS 203 ML-KEM-768 encapsulation (Alice) and decapsulation (Bob)
  if (options.mode === 'HYBRID_X25519_MLKEM768') {
    const bobMlKemPub = hexToBytes(bobBundle.mlKem768PublicKeyHex);
    const bobMlKemPriv = hexToBytes(bobBundle.mlKem768SecretKeyHex);

    const encap = ml_kem768.encapsulate(bobMlKemPub);
    mlKemCiphertextHex = bytesToHex(encap.cipherText);

    const decapSharedSecret = ml_kem768.decapsulate(encap.cipherText, bobMlKemPriv);

    // Combine X25519 shared secret (32B) || ML-KEM-768 shared secret (32B)
    aliceCombinedIkm = concatBytes(aliceDhSecret, encap.sharedSecret);
    bobCombinedIkm = concatBytes(bobDhSecret, decapSharedSecret);
  }

  // 3. Context-bound HKDF-SHA-256 root/epoch-0 derivation
  const kemTranscriptHash = mlKemCiphertextHex
    ? bytesToHex(sha256(hexToBytes(mlKemCiphertextHex)))
    : 'none';

  const rootSalt = sha256(
    utf8ToBytes(
      `ARX-ROOT-SALT|${protocolVersion}|${sessionId}|${aliceBundle.x25519PublicKeyHex}|${bobBundle.x25519PublicKeyHex}|${kemTranscriptHash}`
    )
  );
  const rootInfo = utf8ToBytes(
    `ARX-EPOCH0-SECRET|v1|proto=${protocolVersion}|sid=${sessionId}|initiator=alice|responder=bob`
  );

  const aliceEpoch0Secret = hkdf(sha256, aliceCombinedIkm, rootSalt, rootInfo, 32);
  const bobEpoch0Secret = hkdf(sha256, bobCombinedIkm, rootSalt, rootInfo, 32);

  // Derive separate directional chains for Epoch 0
  const aliceChainA2B = deriveDirectionalChainKey(aliceEpoch0Secret, protocolVersion, sessionId, 'A2B', 0);
  const aliceChainB2A = deriveDirectionalChainKey(aliceEpoch0Secret, protocolVersion, sessionId, 'B2A', 0);

  const bobChainA2B = deriveDirectionalChainKey(bobEpoch0Secret, protocolVersion, sessionId, 'A2B', 0);
  const bobChainB2A = deriveDirectionalChainKey(bobEpoch0Secret, protocolVersion, sessionId, 'B2A', 0);

  const safetyFingerprint = computeSafetyFingerprint(
    sessionId,
    aliceBundle.x25519PublicKeyHex,
    bobBundle.x25519PublicKeyHex,
    options.mode,
    options.mode === 'HYBRID_X25519_MLKEM768' ? bobBundle.mlKem768PublicKeyHex : undefined
  );

  const handshake: SessionInitHandshake = {
    sessionId,
    mode: options.mode,
    protocolVersion,
    epochSize,
    initiator: 'alice',
    responder: 'bob',
    aliceX25519PublicHex: aliceBundle.x25519PublicKeyHex,
    bobX25519PublicHex: bobBundle.x25519PublicKeyHex,
    bobMlKem768PublicHex:
      options.mode === 'HYBRID_X25519_MLKEM768' ? bobBundle.mlKem768PublicKeyHex : undefined,
    mlKem768CiphertextHex: mlKemCiphertextHex,
    createdAt: Date.now(),
  };

  const aliceState: EndpointSessionState = {
    owner: 'alice',
    peer: 'bob',
    sessionId,
    mode: options.mode,
    protocolVersion,
    epochSize,
    safetyFingerprint,
    sendDirection: 'A2B',
    sendEpoch: 0,
    sendMsgNum: 0,
    sendEpochSecretHex: bytesToHex(aliceEpoch0Secret),
    sendChainKeyHex: bytesToHex(aliceChainA2B),
    recvDirection: 'B2A',
    recvEpoch: 0,
    recvMsgNum: 0,
    recvEpochSecretHex: bytesToHex(aliceEpoch0Secret),
    recvChainKeyHex: bytesToHex(aliceChainB2A),
    seenMessageKeys: [],
    skippedKeys: {},
    maxSkip: MAX_SKIP_KEYS,
    sentEnvelopesBySeq: {},
    localKeyEvolutionLog: [],
  };

  const bobState: EndpointSessionState = {
    owner: 'bob',
    peer: 'alice',
    sessionId,
    mode: options.mode,
    protocolVersion,
    epochSize,
    safetyFingerprint,
    sendDirection: 'B2A',
    sendEpoch: 0,
    sendMsgNum: 0,
    sendEpochSecretHex: bytesToHex(bobEpoch0Secret),
    sendChainKeyHex: bytesToHex(bobChainB2A),
    recvDirection: 'A2B',
    recvEpoch: 0,
    recvMsgNum: 0,
    recvEpochSecretHex: bytesToHex(bobEpoch0Secret),
    recvChainKeyHex: bytesToHex(bobChainA2B),
    seenMessageKeys: [],
    skippedKeys: {},
    maxSkip: MAX_SKIP_KEYS,
    sentEnvelopesBySeq: {},
    localKeyEvolutionLog: [],
  };

  return { handshake, aliceState, bobState };
}

/**
 * Encrypts a message at the sending endpoint, advancing the sender's chain and epoch state.
 */
export async function encryptEndpointMessage(
  state: EndpointSessionState,
  plaintext: string,
  options?: { allowLocalPlaintextDemo?: boolean }
): Promise<EncryptResult> {
  const t0 = nowPerf();

  if (state.mode === 'LOCAL_PLAINTEXT_BASELINE' && !options?.allowLocalPlaintextDemo) {
    throw new Error('Local Plaintext Baseline mode requires explicit local demo authorization.');
  }

  let currentEpoch = state.sendEpoch;
  let currentMsgNum = state.sendMsgNum;
  let currentEpochSecretHex = state.sendEpochSecretHex;
  let currentChainKeyHex = state.sendChainKeyHex;

  // Check if we need to transition to a new epoch before encrypting this message
  if (currentMsgNum >= state.epochSize) {
    const nextEpoch = currentEpoch + 1;
    const advanced = advanceEpochSecret(
      hexToBytes(currentEpochSecretHex),
      state.protocolVersion,
      state.sessionId,
      state.sendDirection,
      nextEpoch
    );
    currentEpoch = nextEpoch;
    currentMsgNum = 0;
    currentEpochSecretHex = advanced.nextEpochSecretHex;
    currentChainKeyHex = advanced.nextChainKeyHex;
  }

  // Perform per-message KDF ratchet step
  const step = kdfRatchetStep(
    currentChainKeyHex,
    state.protocolVersion,
    state.sessionId,
    state.owner,
    state.peer,
    state.sendDirection,
    currentEpoch,
    currentMsgNum
  );

  const header: AuthenticatedHeader = {
    protocolVersion: state.protocolVersion,
    sessionId: state.sessionId,
    sender: state.owner,
    recipient: state.peer,
    direction: state.sendDirection,
    epoch: currentEpoch,
    msgNum: currentMsgNum,
    nonceHex: step.nonceHex,
  };

  const aadBytes = serializeAuthenticatedHeader(header);
  const plaintextBytes = textEncoder.encode(plaintext);

  let ciphertextHex = '';
  let authTagHex = '';
  let cryptoOverheadBytes = 0;

  if (state.mode === 'LOCAL_PLAINTEXT_BASELINE') {
    ciphertextHex = bytesToHex(plaintextBytes);
    authTagHex = '';
    cryptoOverheadBytes = 0;
  } else {
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw',
      step.messageKeyBytes as Uint8Array<ArrayBuffer>,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );
    const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: step.nonceBytes as Uint8Array<ArrayBuffer>,
        additionalData: aadBytes as Uint8Array<ArrayBuffer>,
        tagLength: 128,
      },
      cryptoKey,
      plaintextBytes as Uint8Array<ArrayBuffer>
    );
    const encryptedBytes = new Uint8Array(encryptedBuffer);
    // WebCrypto AES-GCM appends the 16-byte authentication tag at the end of ciphertext
    const rawCiphertext = encryptedBytes.slice(0, encryptedBytes.length - 16);
    const authTag = encryptedBytes.slice(encryptedBytes.length - 16);

    ciphertextHex = bytesToHex(rawCiphertext);
    authTagHex = bytesToHex(authTag);
    // Raw cryptographic overhead = 12B nonce + 16B tag = 28 bytes (plus authenticated header)
    cryptoOverheadBytes = 12 + 16;
  }

  const randId = new Uint8Array(8);
  globalThis.crypto.getRandomValues(randId);
  const envelopeId = `env-${currentEpoch}-${currentMsgNum}-${bytesToHex(randId)}`;

  const tempEnvelope: EncryptedEnvelope = {
    envelopeId,
    header,
    mode: state.mode,
    ciphertextHex,
    authTagHex,
    timestampMs: Date.now(),
    plaintextByteLength: plaintextBytes.length,
    serializedEnvelopeBytes: 0,
    cryptoOverheadBytes,
    tamperedFlag: 'NONE',
  };

  const serializedBytes = textEncoder.encode(JSON.stringify(tempEnvelope)).length;
  const envelope: EncryptedEnvelope = {
    ...tempEnvelope,
    serializedEnvelopeBytes: serializedBytes,
  };

  const seqKey = `${currentEpoch}:${currentMsgNum}`;
  const updatedState: EndpointSessionState = {
    ...state,
    sendEpoch: currentEpoch,
    sendMsgNum: currentMsgNum + 1,
    sendEpochSecretHex: currentEpochSecretHex,
    sendChainKeyHex: step.nextChainKeyHex,
    sentEnvelopesBySeq: {
      ...state.sentEnvelopesBySeq,
      [seqKey]: envelope,
    },
    localKeyEvolutionLog: [
      ...state.localKeyEvolutionLog,
      {
        direction: state.sendDirection,
        epoch: currentEpoch,
        msgNum: currentMsgNum,
        nonceHex: step.nonceHex,
        keyFingerprint: step.keyFingerprint,
        timestamp: Date.now(),
      },
    ],
  };

  const t1 = nowPerf();
  return {
    envelope,
    updatedState,
    executionTimeMs: Number((t1 - t0).toFixed(3)),
    localKeyFingerprint: step.keyFingerprint,
  };
}

/**
 * Safely retrieves a previously encrypted envelope for delivery retry without re-encrypting
 * or reusing a nonce/key pair.
 */
export function getEnvelopeForRetry(
  state: EndpointSessionState,
  epoch: number,
  msgNum: number
): EncryptedEnvelope | undefined {
  return state.sentEnvelopesBySeq[`${epoch}:${msgNum}`];
}

/**
 * Decrypts and authenticates an incoming envelope at the receiving endpoint.
 * Enforces:
 * - Session & direction binding
 * - Explicit replay detection before and after key lookup
 * - Bounded out-of-order skipped-key derivation (MAX_SKIP_KEYS = 32)
 * - Atomic state commitment ONLY after AES-256-GCM authentication succeeds
 */
export async function decryptEndpointMessage(
  state: EndpointSessionState,
  envelope: EncryptedEnvelope,
  options?: { allowLocalPlaintextDemo?: boolean }
): Promise<DecryptResult> {
  const t0 = nowPerf();
  const { header } = envelope;

  // 1. Validate session context
  if (
    header.sessionId !== state.sessionId ||
    header.direction !== state.recvDirection ||
    header.recipient !== state.owner ||
    header.sender !== state.peer
  ) {
    return {
      success: false,
      errorType: 'SESSION_MISMATCH',
      errorMessage: 'Envelope session ID, direction, or participant identities do not match active session.',
      updatedState: state,
      executionTimeMs: Number((nowPerf() - t0).toFixed(3)),
    };
  }

  if (envelope.mode === 'LOCAL_PLAINTEXT_BASELINE' && !options?.allowLocalPlaintextDemo) {
    return {
      success: false,
      errorType: 'PLAINTEXT_DISABLED',
      errorMessage: 'Local plaintext baseline mode is disabled.',
      updatedState: state,
      executionTimeMs: Number((nowPerf() - t0).toFixed(3)),
    };
  }

  const msgId = `${header.epoch}:${header.msgNum}`;

  // 2. Explicit Replay Protection check
  if (state.seenMessageKeys.includes(msgId)) {
    return {
      success: false,
      errorType: 'REPLAY_DETECTED',
      errorMessage: `Replay rejected: Record (epoch ${header.epoch}, msg #${header.msgNum}) was already accepted.`,
      updatedState: state,
      executionTimeMs: Number((nowPerf() - t0).toFixed(3)),
    };
  }

  // Check if message is from an older position that was already passed and not in skippedKeys
  if (
    (header.epoch < state.recvEpoch ||
      (header.epoch === state.recvEpoch && header.msgNum < state.recvMsgNum)) &&
    !state.skippedKeys[msgId]
  ) {
    return {
      success: false,
      errorType: 'REPLAY_DETECTED',
      errorMessage: `Replay or stale record rejected: (epoch ${header.epoch}, msg #${header.msgNum}) precedes receiver watermark.`,
      updatedState: state,
      executionTimeMs: Number((nowPerf() - t0).toFixed(3)),
    };
  }

  // 3. Determine candidate message key & tentative state WITHOUT mutating `state`
  let candidateMessageKeyBytes: Uint8Array;
  let candidateNonceBytes: Uint8Array;
  let candidateKeyFingerprint: string;

  let tentativeEpoch = state.recvEpoch;
  let tentativeMsgNum = state.recvMsgNum;
  let tentativeEpochSecretHex = state.recvEpochSecretHex;
  let tentativeChainKeyHex = state.recvChainKeyHex;
  const tentativeSkippedKeys: Record<string, SkippedKeyEntry> = { ...state.skippedKeys };

  if (tentativeSkippedKeys[msgId]) {
    // Message was previously skipped and cached
    const cached = tentativeSkippedKeys[msgId];
    candidateMessageKeyBytes = hexToBytes(cached.messageKeyHex);
    candidateNonceBytes = hexToBytes(cached.nonceHex);
    candidateKeyFingerprint = cached.keyFingerprint;
    delete tentativeSkippedKeys[msgId];
  } else {
    if (header.epoch < 0 || header.msgNum < 0 || header.msgNum >= state.epochSize) {
      return {
        success: false,
        errorType: 'AUTH_FAILED',
        errorMessage: 'AES-256-GCM authentication failed: Invalid or tampered epoch/message number in record header.',
        updatedState: state,
        executionTimeMs: Number((nowPerf() - t0).toFixed(3)),
      };
    }

    const totalDistance =
      (header.epoch - tentativeEpoch) * state.epochSize + (header.msgNum - tentativeMsgNum);

    if (totalDistance < 0) {
      return {
        success: false,
        errorType: 'REPLAY_DETECTED',
        errorMessage: `Stale record (epoch ${header.epoch}, msg #${header.msgNum}) rejected.`,
        updatedState: state,
        executionTimeMs: Number((nowPerf() - t0).toFixed(3)),
      };
    }

    if (totalDistance > state.maxSkip) {
      return {
        success: false,
        errorType: 'OUT_OF_ORDER_LIMIT',
        errorMessage: `Out-of-order jump (${totalDistance} messages) exceeds bounded skip window (${state.maxSkip}).`,
        updatedState: state,
        executionTimeMs: Number((nowPerf() - t0).toFixed(3)),
      };
    }

    // Advance tentatively through any skipped messages up to target (header.epoch, header.msgNum)
    let stepsRemaining = totalDistance;
    while (stepsRemaining > 0) {
      while (tentativeMsgNum >= state.epochSize) {
        const nextEpoch = tentativeEpoch + 1;
        const adv = advanceEpochSecret(
          hexToBytes(tentativeEpochSecretHex),
          state.protocolVersion,
          state.sessionId,
          state.recvDirection,
          nextEpoch
        );
        tentativeEpoch = nextEpoch;
        tentativeMsgNum -= state.epochSize;
        tentativeEpochSecretHex = adv.nextEpochSecretHex;
        tentativeChainKeyHex = adv.nextChainKeyHex;
      }

      const skippedStep = kdfRatchetStep(
        tentativeChainKeyHex,
        state.protocolVersion,
        state.sessionId,
        state.peer,
        state.owner,
        state.recvDirection,
        tentativeEpoch,
        tentativeMsgNum
      );

      const skipId = `${tentativeEpoch}:${tentativeMsgNum}`;
      tentativeSkippedKeys[skipId] = {
        messageKeyHex: skippedStep.messageKeyHex,
        nonceHex: skippedStep.nonceHex,
        keyFingerprint: skippedStep.keyFingerprint,
      };

      tentativeChainKeyHex = skippedStep.nextChainKeyHex;
      tentativeMsgNum += 1;
      stepsRemaining -= 1;
    }

    // Check epoch boundary right at target message
    while (tentativeMsgNum >= state.epochSize) {
      const nextEpoch = tentativeEpoch + 1;
      const adv = advanceEpochSecret(
        hexToBytes(tentativeEpochSecretHex),
        state.protocolVersion,
        state.sessionId,
        state.recvDirection,
        nextEpoch
      );
      tentativeEpoch = nextEpoch;
      tentativeMsgNum -= state.epochSize;
      tentativeEpochSecretHex = adv.nextEpochSecretHex;
      tentativeChainKeyHex = adv.nextChainKeyHex;
    }

    // Now derive the key for the target message itself
    const targetStep = kdfRatchetStep(
      tentativeChainKeyHex,
      state.protocolVersion,
      state.sessionId,
      state.peer,
      state.owner,
      state.recvDirection,
      tentativeEpoch,
      tentativeMsgNum
    );

    candidateMessageKeyBytes = targetStep.messageKeyBytes;
    candidateNonceBytes = targetStep.nonceBytes;
    candidateKeyFingerprint = targetStep.keyFingerprint;
    tentativeChainKeyHex = targetStep.nextChainKeyHex;
    tentativeMsgNum += 1;
  }

  // 4. Verify & Decrypt
  const aadBytes = serializeAuthenticatedHeader(header);

  if (envelope.mode === 'LOCAL_PLAINTEXT_BASELINE') {
    const ptBytes = hexToBytes(envelope.ciphertextHex);
    const plaintext = textDecoder.decode(ptBytes);
    const committedState: EndpointSessionState = {
      ...state,
      recvEpoch: tentativeEpoch,
      recvMsgNum: tentativeMsgNum,
      recvEpochSecretHex: tentativeEpochSecretHex,
      recvChainKeyHex: tentativeChainKeyHex,
      skippedKeys: tentativeSkippedKeys,
      seenMessageKeys: [...state.seenMessageKeys, msgId],
      localKeyEvolutionLog: [
        ...state.localKeyEvolutionLog,
        {
          direction: state.recvDirection,
          epoch: header.epoch,
          msgNum: header.msgNum,
          nonceHex: header.nonceHex,
          keyFingerprint: candidateKeyFingerprint,
          timestamp: Date.now(),
        },
      ],
    };
    return {
      success: true,
      plaintext,
      updatedState: committedState,
      executionTimeMs: Number((nowPerf() - t0).toFixed(3)),
      localKeyFingerprint: candidateKeyFingerprint,
    };
  }

  try {
    // Ensure transmitted nonce matches derived nonce; if tampered in header, AAD or IV check will fail
    const rawCiphertext = hexToBytes(envelope.ciphertextHex);
    const authTag = hexToBytes(envelope.authTagHex);
    if (authTag.length !== 16) {
      throw new Error('Invalid GCM authentication tag length');
    }

    const combinedCiphertextAndTag = concatBytes(rawCiphertext, authTag);
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'raw',
      candidateMessageKeyBytes as Uint8Array<ArrayBuffer>,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    const decryptedBuffer = await globalThis.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: candidateNonceBytes as Uint8Array<ArrayBuffer>,
        additionalData: aadBytes as Uint8Array<ArrayBuffer>,
        tagLength: 128,
      },
      cryptoKey,
      combinedCiphertextAndTag as Uint8Array<ArrayBuffer>
    );

    const plaintext = textDecoder.decode(new Uint8Array(decryptedBuffer));

    // 5. ONLY after successful AES-256-GCM authentication do we commit state advancement!
    const committedState: EndpointSessionState = {
      ...state,
      recvEpoch: tentativeEpoch,
      recvMsgNum: tentativeMsgNum,
      recvEpochSecretHex: tentativeEpochSecretHex,
      recvChainKeyHex: tentativeChainKeyHex,
      skippedKeys: tentativeSkippedKeys,
      seenMessageKeys: [...state.seenMessageKeys, msgId],
      localKeyEvolutionLog: [
        ...state.localKeyEvolutionLog,
        {
          direction: state.recvDirection,
          epoch: header.epoch,
          msgNum: header.msgNum,
          nonceHex: header.nonceHex,
          keyFingerprint: candidateKeyFingerprint,
          timestamp: Date.now(),
        },
      ],
    };

    return {
      success: true,
      plaintext,
      updatedState: committedState,
      executionTimeMs: Number((nowPerf() - t0).toFixed(3)),
      localKeyFingerprint: candidateKeyFingerprint,
    };
  } catch {
    // Authentication failed! Return untouched `state` so receiver chain is never corrupted by tampered records.
    return {
      success: false,
      errorType: 'AUTH_FAILED',
      errorMessage:
        'AES-256-GCM authentication failed: Ciphertext, authentication tag, or authenticated header was modified in transit.',
      updatedState: state,
      executionTimeMs: Number((nowPerf() - t0).toFixed(3)),
    };
  }
}

/**
 * Helper to flip 1 bit in the ciphertext hex without recomputing the GCM authentication tag.
 */
export function tamperCiphertextBitFlip(envelope: EncryptedEnvelope): EncryptedEnvelope {
  const bytes = hexToBytes(envelope.ciphertextHex);
  if (bytes.length > 0) {
    bytes[Math.floor(bytes.length / 2)] ^= 0x01; // Flip least-significant bit of middle byte
  } else {
    return {
      ...envelope,
      ciphertextHex: '01',
      tamperedFlag: 'CIPHERTEXT_BITFLIP',
    };
  }
  return {
    ...envelope,
    ciphertextHex: bytesToHex(bytes),
    tamperedFlag: 'CIPHERTEXT_BITFLIP',
  };
}

/**
 * Helper to modify the authenticated record header without recomputing the GCM authentication tag.
 */
export function tamperAuthenticatedHeader(envelope: EncryptedEnvelope): EncryptedEnvelope {
  // Modify the nonceHex in the header (which is bound into canonical AAD bytes)
  const nonceBytes = hexToBytes(envelope.header.nonceHex);
  nonceBytes[0] ^= 0xff;
  return {
    ...envelope,
    header: {
      ...envelope.header,
      nonceHex: bytesToHex(nonceBytes),
    },
    tamperedFlag: 'HEADER_MODIFIED',
  };
}

/**
 * Helper to corrupt the 16-byte AES-GCM authentication tag.
 */
export function tamperAuthTag(envelope: EncryptedEnvelope): EncryptedEnvelope {
  const tagBytes = hexToBytes(envelope.authTagHex);
  if (tagBytes.length > 0) {
    tagBytes[tagBytes.length - 1] ^= 0x80;
  }
  return {
    ...envelope,
    authTagHex: bytesToHex(tagBytes),
    tamperedFlag: 'TAG_CORRUPTED',
  };
}
