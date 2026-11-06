import React, { useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  ChevronLeft,
  ChevronRight,
  Play,
  Pause,
  RotateCcw,
} from 'lucide-react';
import {
  decryptEndpointMessage,
  encryptEndpointMessage,
  establishSessionPair,
  formatCanonicalHeaderString,
  generateIdentityKeyBundle,
  kdfRatchetStep,
  tamperAuthenticatedHeader,
  tamperCiphertextBitFlip,
  type EncryptionMode,
} from '../crypto/arxCrypto.ts';

export type FlowScenarioMode =
  | 'NORMAL_E2EE'
  | 'TAMPER_CIPHERTEXT'
  | 'TAMPER_HEADER_AAD'
  | 'REPLAY_DUPLICATE'
  | 'EPOCH_ROLLOVER';

interface VisualFlowSimulatorViewProps {
  activeEncryptionMode: EncryptionMode;
  epochSize: number;
  onTriggerLiveNormal: () => Promise<void>;
  onTriggerLiveTamperCipher: () => Promise<void>;
  onTriggerLiveTamperHeader: () => Promise<void>;
  onTriggerLiveReplay: () => Promise<void>;
}

interface ComputedSimulationTrace {
  scenario: FlowScenarioMode;
  mode: EncryptionMode;
  plaintext: string;
  plaintextHex: string;
  plaintextBytes: number;
  sessionId: string;
  protocolVersion: string;
  safetyFingerprint: string;
  aliceX25519PubHex: string;
  bobX25519PubHex: string;
  bobMlKemPubBytes: number;
  mlKemCiphertextHex: string;
  epochBefore: number;
  msgNumBefore: number;
  epochUsed: number;
  msgNumUsed: number;
  epochRolloverOccurred: boolean;
  chainKeyBeforeHex: string;
  nextChainKeyHex: string;
  derivedMessageKeyHex: string;
  derivedKeyFingerprint: string;
  derivedNonceHex: string;
  canonicalAadString: string;
  canonicalAadHex: string;
  originalCiphertextHex: string;
  originalAuthTagHex: string;
  transmittedCiphertextHex: string;
  transmittedNonceHex: string;
  transmittedCanonicalAadString: string;
  transmittedAuthTagHex: string;
  recomputedExpectedTagHex: string;
  serializedEnvelopeBytes: number;
  wirePacketBytes: number;
  bobVerifySuccess: boolean;
  bobErrorType?: string;
  bobErrorMessage?: string;
  bobDecryptedPlaintext?: string;
  bobStateCommitted: boolean;
}

interface StageDescriptor {
  stageNumber: number;
  shortTitle: string;
  title: string;
  algorithmBadge: string;
  actorZone: 'ALICE_ENDPOINT' | 'NETWORK_AND_RELAY' | 'PACKETGUARD_TAP' | 'BOB_ENDPOINT';
  summary: string;
}

const FLOW_STAGES: StageDescriptor[] = [
  {
    stageNumber: 1,
    shortTitle: '1. Key Exchange',
    title: 'Stage 1: Hybrid Key Agreement & Safety Fingerprint',
    algorithmBadge: 'X25519 + FIPS 203 ML-KEM-768 + SHA-256',
    actorZone: 'ALICE_ENDPOINT',
    summary:
      'Alice and Bob exchange 32B X25519 public keys and Bob’s 1184B ML-KEM-768 public key, encapsulating a 1088B post-quantum ciphertext and computing an out-of-band 30-char SHA-256 Safety Fingerprint.',
  },
  {
    stageNumber: 2,
    shortTitle: '2. Root & Epoch KDF',
    title: 'Stage 2: Context-Bound Root & Directional Chain Derivation',
    algorithmBadge: 'HKDF-SHA-256 (Extract + Expand)',
    actorZone: 'ALICE_ENDPOINT',
    summary:
      'Both shared secrets (DH_SS || KEM_SS) are extracted and expanded with the session transcript to derive Epoch 0 and two domain-separated 256-bit directional chains (A2B and B2A).',
  },
  {
    stageNumber: 3,
    shortTitle: '3. Msg Ratchet',
    title: 'Stage 3: One-Way Per-Message KDF Ratchet Step',
    algorithmBadge: 'HKDF-SHA-256 -> 76-Byte OKM',
    actorZone: 'ALICE_ENDPOINT',
    summary:
      'Alice’s current 32B Sending Chain Key enters a one-way HKDF-SHA-256 step bound to (sessionId, A2B, epoch, msgNum), producing a 32B NextChainKey, a 32B ephemeral MessageKey, and a 12B Nonce.',
  },
  {
    stageNumber: 4,
    shortTitle: '4. AES-256-GCM',
    title: 'Stage 4: Canonical Header (AAD) & AES-256-GCM Encryption',
    algorithmBadge: 'AES-256-GCM (96-bit IV, 128-bit Tag)',
    actorZone: 'ALICE_ENDPOINT',
    summary:
      'Alice serializes the deterministic UTF-8 Authenticated Header (AAD) and encrypts the plaintext under the ephemeral 256-bit MessageKey, producing raw Ciphertext and a 16-byte (128-bit) GCM Authentication Tag.',
  },
  {
    stageNumber: 5,
    shortTitle: '5. Packet Framing',
    title: 'Stage 5: JSON Serialization & TCP/IP Loopback Encapsulation',
    algorithmBadge: 'JSON -> HTTP POST -> TCP PSH,ACK -> IPv4',
    actorZone: 'NETWORK_AND_RELAY',
    summary:
      'The encrypted envelope is serialized into JSON and framed inside HTTP POST, TCP (PSH,ACK), IPv4, and loopback headers—explaining why 1 application message generates 3 network packets on the wire.',
  },
  {
    stageNumber: 6,
    shortTitle: '6. Relay & Faults',
    title: 'Stage 6: Untrusted SQLite Relay & Active Tamper / Replay Zone',
    algorithmBadge: 'SQLite WAL + Controlled MITM Fault Injection',
    actorZone: 'NETWORK_AND_RELAY',
    summary:
      'The untrusted Relay Server stores the ciphertext envelope without keys. If an experiment is armed, the relay flips 1 bit of ciphertext, alters the AAD header nonce, or replays a duplicate record.',
  },
  {
    stageNumber: 7,
    shortTitle: '7. PacketGuard Tap',
    title: 'Stage 7: PacketGuard Independent Metadata Inspection & Heuristics',
    algorithmBadge: 'Sliding-Window Metadata Rules + Shannon Entropy',
    actorZone: 'PACKETGUARD_TAP',
    summary:
      'PacketGuard passively inspects packet headers (IPs, ports, byte sizes, TCP flags, ARP/DNS fields) to compute throughput and trigger heuristic alerts—while message content remains opaque ciphertext.',
  },
  {
    stageNumber: 8,
    shortTitle: '8. Bob Verification',
    title: 'Stage 8: Bob Replay Gate, GCM Tag Verification & Atomic State Commit',
    algorithmBadge: 'Replay Watermark + AES-256-GCM Verify',
    actorZone: 'BOB_ENDPOINT',
    summary:
      'Bob checks his seen-message replay watermark first, tentatively derives the candidate MessageKey, verifies the 128-bit GCM tag over (Canonical AAD + Ciphertext), and commits state ONLY if authentic.',
  },
];

export const VisualFlowSimulatorView: React.FC<VisualFlowSimulatorViewProps> = ({
  activeEncryptionMode,
  epochSize,
  onTriggerLiveNormal,
  onTriggerLiveTamperCipher,
  onTriggerLiveTamperHeader,
  onTriggerLiveReplay,
}) => {
  const [scenario, setScenario] = useState<FlowScenarioMode>('NORMAL_E2EE');
  const [customPlaintext, setCustomPlaintext] = useState<string>(
    'Authorize transfer: $5,000 to Vault #42'
  );
  const [currentStage, setCurrentStage] = useState<number>(1);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [stepIntervalMs, setStepIntervalMs] = useState<number>(2600);
  const [trace, setTrace] = useState<ComputedSimulationTrace | null>(null);
  const [isExecutingLive, setIsExecutingLive] = useState<boolean>(false);

  // Recompute real cryptographic trace whenever scenario, plaintext, mode, or epochSize changes
  useEffect(() => {
    let cancelled = false;

    async function computeRealTrace() {
      const modeToUse: EncryptionMode =
        activeEncryptionMode === 'LOCAL_PLAINTEXT_BASELINE'
          ? 'HYBRID_X25519_MLKEM768'
          : activeEncryptionMode;

      const aliceId = generateIdentityKeyBundle('alice');
      const bobId = generateIdentityKeyBundle('bob');
      let { handshake, aliceState, bobState } = establishSessionPair(aliceId, bobId, {
        mode: modeToUse,
        epochSize,
        sessionId: 'sid-visual-flow-demo',
      });

      // If EPOCH_ROLLOVER scenario is selected, advance Alice & Bob right to the last message of Epoch 0
      // so the next message triggers an Epoch 0 -> Epoch 1 transition!
      if (scenario === 'EPOCH_ROLLOVER') {
        for (let i = 0; i < epochSize; i++) {
          const preEnc = await encryptEndpointMessage(aliceState, `Warmup #${i}`);
          aliceState = preEnc.updatedState;
          const preDec = await decryptEndpointMessage(bobState, preEnc.envelope);
          bobState = preDec.updatedState;
        }
      }

      const epochBefore = aliceState.sendEpoch;
      const msgNumBefore = aliceState.sendMsgNum;
      const chainKeyBeforeHex = aliceState.sendChainKeyHex;

      // Encrypt the user's custom plaintext at Alice's endpoint
      const textToEncrypt = customPlaintext.trim() || 'Hello Bob!';
      const encResult = await encryptEndpointMessage(aliceState, textToEncrypt);
      const originalEnvelope = encResult.envelope;

      // Inspect the exact KDF step values for Stage 3 educational display
      const kdfStepInspect = kdfRatchetStep(
        scenario === 'EPOCH_ROLLOVER'
          ? // After rollover, encryptEndpointMessage derived epoch 1's initial chain key first
            chainKeyBeforeHex
          : chainKeyBeforeHex,
        aliceState.protocolVersion,
        aliceState.sessionId,
        'alice',
        'bob',
        'A2B',
        originalEnvelope.header.epoch,
        originalEnvelope.header.msgNum
      );

      // Apply scenario-specific relay behavior in Stage 6
      let transmittedEnvelope = originalEnvelope;
      if (scenario === 'TAMPER_CIPHERTEXT') {
        transmittedEnvelope = tamperCiphertextBitFlip(originalEnvelope);
      } else if (scenario === 'TAMPER_HEADER_AAD') {
        transmittedEnvelope = tamperAuthenticatedHeader(originalEnvelope);
      } else if (scenario === 'REPLAY_DUPLICATE') {
        // First deliver the original envelope once so Bob records (epoch, msgNum) in seenMessageKeys
        const firstAccept = await decryptEndpointMessage(bobState, originalEnvelope);
        bobState = firstAccept.updatedState;
      }

      // Now run Bob's actual endpoint verification on the transmitted envelope
      const bobResult = await decryptEndpointMessage(bobState, transmittedEnvelope);

      // Compute a deterministic visual representation of what tag Bob's GHASH expected vs received
      const recomputedExpectedTagHex =
        scenario === 'TAMPER_CIPHERTEXT' || scenario === 'TAMPER_HEADER_AAD'
          ? bytesToHex(
              sha256(
                utf8ToBytes(
                  `EXPECTED-TAG|${formatCanonicalHeaderString(
                    transmittedEnvelope.header
                  )}|${transmittedEnvelope.ciphertextHex}`
                )
              )
            ).slice(0, 32)
          : originalEnvelope.authTagHex;

      if (!cancelled) {
        setTrace({
          scenario,
          mode: modeToUse,
          plaintext: textToEncrypt,
          plaintextHex: bytesToHex(utf8ToBytes(textToEncrypt)),
          plaintextBytes: utf8ToBytes(textToEncrypt).length,
          sessionId: handshake.sessionId,
          protocolVersion: handshake.protocolVersion,
          safetyFingerprint: aliceState.safetyFingerprint,
          aliceX25519PubHex: aliceId.x25519PublicKeyHex,
          bobX25519PubHex: bobId.x25519PublicKeyHex,
          bobMlKemPubBytes: bobId.mlKem768PublicKeyHex.length / 2,
          mlKemCiphertextHex: handshake.mlKem768CiphertextHex || '',
          epochBefore,
          msgNumBefore,
          epochUsed: originalEnvelope.header.epoch,
          msgNumUsed: originalEnvelope.header.msgNum,
          epochRolloverOccurred: originalEnvelope.header.epoch > epochBefore,
          chainKeyBeforeHex,
          nextChainKeyHex: encResult.updatedState.sendChainKeyHex,
          derivedMessageKeyHex: kdfStepInspect.messageKeyHex,
          derivedKeyFingerprint: encResult.localKeyFingerprint,
          derivedNonceHex: originalEnvelope.header.nonceHex,
          canonicalAadString: formatCanonicalHeaderString(originalEnvelope.header),
          canonicalAadHex: bytesToHex(
            utf8ToBytes(formatCanonicalHeaderString(originalEnvelope.header))
          ),
          originalCiphertextHex: originalEnvelope.ciphertextHex,
          originalAuthTagHex: originalEnvelope.authTagHex,
          transmittedCiphertextHex: transmittedEnvelope.ciphertextHex,
          transmittedNonceHex: transmittedEnvelope.header.nonceHex,
          transmittedCanonicalAadString: formatCanonicalHeaderString(
            transmittedEnvelope.header
          ),
          transmittedAuthTagHex: transmittedEnvelope.authTagHex,
          recomputedExpectedTagHex,
          serializedEnvelopeBytes: originalEnvelope.serializedEnvelopeBytes,
          wirePacketBytes: originalEnvelope.serializedEnvelopeBytes + 218 + 44,
          bobVerifySuccess: bobResult.success,
          bobErrorType: bobResult.errorType,
          bobErrorMessage: bobResult.errorMessage,
          bobDecryptedPlaintext: bobResult.plaintext,
          bobStateCommitted: bobResult.success,
        });
      }
    }

    computeRealTrace();
    return () => {
      cancelled = true;
    };
  }, [scenario, customPlaintext, activeEncryptionMode, epochSize]);

  // Automatic animation playback timer
  useEffect(() => {
    if (!isPlaying) return;

    const timer = setInterval(() => {
      setCurrentStage((prev) => {
        if (prev >= 8) {
          setIsPlaying(false);
          return 8;
        }
        return prev + 1;
      });
    }, stepIntervalMs);

    return () => clearInterval(timer);
  }, [isPlaying, stepIntervalMs]);

  // Keyboard navigation: Left Arrow -> Prev, Right Arrow -> Next, Space -> Toggle Play/Pause
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Don't intercept if user is typing into an input field or textarea
      const target = e.target as HTMLElement | null;
      if (
        target &&
        (target.tagName === 'INPUT' ||
          target.tagName === 'TEXTAREA' ||
          target.isContentEditable)
      ) {
        return;
      }

      if (e.key === 'ArrowLeft') {
        e.preventDefault();
        setIsPlaying(false);
        setCurrentStage((s) => Math.max(1, s - 1));
      } else if (e.key === 'ArrowRight') {
        e.preventDefault();
        setIsPlaying(false);
        setCurrentStage((s) => Math.min(8, s + 1));
      } else if (e.key === ' ') {
        e.preventDefault();
        setIsPlaying((p) => {
          if (!p && currentStage >= 8) {
            setCurrentStage(1);
          }
          return !p;
        });
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [currentStage]);

  const activeStageMeta = useMemo(
    () => FLOW_STAGES.find((s) => s.stageNumber === currentStage) || FLOW_STAGES[0],
    [currentStage]
  );

  // Compute animated packet X position % across the 4 architectural zones (0% -> 33% -> 66% -> 100%)
  const packetProgressPercent = useMemo(() => {
    switch (currentStage) {
      case 1:
      case 2:
      case 3:
      case 4:
        return 12; // Inside Alice Endpoint
      case 5:
        return 38; // Entering Network & Relay
      case 6:
        return 52; // Inside Relay Server
      case 7:
        return 68; // Passing PacketGuard Tap
      case 8:
        return 88; // Inside Bob Endpoint
      default:
        return 12;
    }
  }, [currentStage]);

  const handleRunOnLiveApp = async () => {
    setIsExecutingLive(true);
    try {
      if (scenario === 'TAMPER_CIPHERTEXT') {
        await onTriggerLiveTamperCipher();
      } else if (scenario === 'TAMPER_HEADER_AAD') {
        await onTriggerLiveTamperHeader();
      } else if (scenario === 'REPLAY_DUPLICATE') {
        await onTriggerLiveReplay();
      } else {
        await onTriggerLiveNormal();
      }
    } finally {
      setIsExecutingLive(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Scenario Control Deck */}
      <div className="p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">
              Interactive Cryptographic &amp; Network Packet Flow Visualizer
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Step-by-step live mathematical execution of X25519, FIPS 203 ML-KEM-768, HKDF-SHA-256 ratcheting, AES-256-GCM AAD binding, TCP/IP framing, Relay tampering, and PacketGuard heuristics
            </p>
          </div>

          {/* Playback Controls */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => {
                if (currentStage >= 8) setCurrentStage(1);
                setIsPlaying((p) => !p);
              }}
              className="px-4 py-2 text-xs font-semibold bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 rounded-md hover:bg-slate-800 dark:hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0"
            >
              {isPlaying ? 'Pause Animation' : currentStage >= 8 ? 'Replay Animation' : 'Play Animated Flow'}
            </button>

            <button
              type="button"
              onClick={() => {
                setIsPlaying(false);
                setCurrentStage((s) => Math.max(1, s - 1));
              }}
              disabled={currentStage <= 1}
              title="Previous Stage (← Left Arrow)"
              className="px-3 py-2 text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 rounded-md hover:bg-slate-200 dark:hover:bg-slate-700 disabled:opacity-40 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1"
            >
              <ChevronLeft className="w-3.5 h-3.5" />
              <span>Prev (←)</span>
            </button>

            <button
              type="button"
              onClick={() => {
                setIsPlaying(false);
                setCurrentStage((s) => Math.min(8, s + 1));
              }}
              disabled={currentStage >= 8}
              title="Next Stage (→ Right Arrow)"
              className="px-3 py-2 text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 rounded-md hover:bg-slate-200 dark:hover:bg-slate-700 disabled:opacity-40 transition-colors whitespace-nowrap shrink-0 flex items-center gap-1"
            >
              <span>Next (→)</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>

            <button
              type="button"
              onClick={() => {
                setIsPlaying(false);
                setCurrentStage(1);
              }}
              title="Reset to Step 1"
              className="px-3 py-2 text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded-md hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
            >
              Reset to Step 1
            </button>

            <select
              value={stepIntervalMs}
              onChange={(e) => setStepIntervalMs(Number(e.target.value))}
              className="px-2.5 py-2 text-xs font-mono bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
            >
              <option value={3600}>Speed: 0.75x (Detailed)</option>
              <option value={2600}>Speed: 1.0x (Classroom)</option>
              <option value={1500}>Speed: 1.75x (Fast)</option>
            </select>
          </div>
        </div>

        {/* Scenario Mode Selector & Live Payload Input */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-end">
          <div className="lg:col-span-7 space-y-1.5">
            <div className="text-xs font-medium text-slate-600 dark:text-slate-400">
              Select Interactive Flow &amp; Fault Scenario:
            </div>
            <div className="flex flex-wrap items-center gap-1.5 p-1 bg-slate-100 dark:bg-slate-800 rounded-lg">
              {(
                [
                  { id: 'NORMAL_E2EE', label: '1. Normal E2EE Flow' },
                  { id: 'TAMPER_CIPHERTEXT', label: '2. Ciphertext 1-Bit Flip' },
                  { id: 'TAMPER_HEADER_AAD', label: '3. Header (AAD) Tamper' },
                  { id: 'REPLAY_DUPLICATE', label: '4. Replay Attack' },
                  { id: 'EPOCH_ROLLOVER', label: '5. Epoch Transition' },
                ] as const
              ).map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    setScenario(item.id);
                    if (
                      item.id === 'TAMPER_CIPHERTEXT' ||
                      item.id === 'TAMPER_HEADER_AAD'
                    ) {
                      setCurrentStage(6);
                    } else if (item.id === 'REPLAY_DUPLICATE') {
                      setCurrentStage(8);
                    } else if (item.id === 'EPOCH_ROLLOVER') {
                      setCurrentStage(2);
                    }
                  }}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                    scenario === item.id
                      ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs font-semibold'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                  }`}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>

          <div className="lg:col-span-5 space-y-1.5">
            <label className="text-xs font-medium text-slate-600 dark:text-slate-400 block">
              Live Test Plaintext Payload (Updates all real hex/keys instantly):
            </label>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={customPlaintext}
                onChange={(e) => setCustomPlaintext(e.target.value)}
                placeholder="Enter plaintext message..."
                className="flex-1 px-3 py-1.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100 font-mono"
              />
              <button
                type="button"
                disabled={isExecutingLive}
                onClick={handleRunOnLiveApp}
                className="px-3 py-1.5 text-xs font-medium bg-emerald-700 text-white rounded-md hover:bg-emerald-800 transition-colors whitespace-nowrap shrink-0"
              >
                {isExecutingLive ? 'Running...' : 'Execute in Live Chat'}
              </button>
            </div>
          </div>
        </div>

        {/* 8-Stage Step Scrubber Bar */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2 pt-2">
          {FLOW_STAGES.map((st) => {
            const isCurrent = st.stageNumber === currentStage;
            const isCompleted = st.stageNumber < currentStage;
            const isFaultStage =
              (scenario === 'TAMPER_CIPHERTEXT' || scenario === 'TAMPER_HEADER_AAD') &&
              (st.stageNumber === 6 || st.stageNumber === 8);
            const isReplayStage =
              scenario === 'REPLAY_DUPLICATE' && st.stageNumber === 8;

            return (
              <button
                key={st.stageNumber}
                type="button"
                onClick={() => {
                  setIsPlaying(false);
                  setCurrentStage(st.stageNumber);
                }}
                className={`p-2.5 rounded-md border text-left transition-all ${
                  isCurrent
                    ? isFaultStage || isReplayStage
                      ? 'bg-amber-50 dark:bg-amber-950/50 border-amber-500 text-slate-900 dark:text-slate-100'
                      : 'bg-slate-900 dark:bg-slate-100 border-slate-900 dark:border-slate-100 text-white dark:text-slate-900'
                    : isCompleted
                    ? 'bg-slate-100 dark:bg-slate-800/80 border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200'
                    : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 hover:border-slate-300'
                }`}
              >
                <div className="text-[11px] font-semibold whitespace-nowrap truncate">
                  {st.shortTitle}
                </div>
                <div
                  className={`text-[10px] font-mono truncate mt-0.5 ${
                    isCurrent
                      ? isFaultStage || isReplayStage
                        ? 'text-amber-700 dark:text-amber-300'
                        : 'text-slate-300 dark:text-slate-600'
                      : 'text-slate-400 dark:text-slate-500'
                  }`}
                >
                  {st.actorZone === 'ALICE_ENDPOINT'
                    ? 'Alice Client'
                    : st.actorZone === 'NETWORK_AND_RELAY'
                    ? 'Relay (:3000)'
                    : st.actorZone === 'PACKETGUARD_TAP'
                    ? 'PacketGuard'
                    : 'Bob Client'}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Animated End-to-End Network Topology & Travelling Packet Canvas */}
      <div className="p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-6 overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-slate-500 dark:text-slate-400">
          <span>
            ACTIVE STAGE {currentStage}/8: {activeStageMeta.title.toUpperCase()}
          </span>
          <span>ALGORITHM: {activeStageMeta.algorithmBadge}</span>
        </div>

        {/* 4-Node Topology Pipeline with Animated Packet Carrier */}
        <div className="relative pt-4 pb-10">
          {/* Connecting Wire Track */}
          <div className="hidden lg:block absolute top-1/2 left-[10%] right-[10%] h-1 -translate-y-1/2 bg-slate-200 dark:bg-slate-800 rounded overflow-hidden">
            <motion.div
              className={`h-full ${
                (scenario === 'TAMPER_CIPHERTEXT' || scenario === 'TAMPER_HEADER_AAD') &&
                currentStage >= 6
                  ? 'bg-amber-600'
                  : scenario === 'REPLAY_DUPLICATE' && currentStage >= 6
                  ? 'bg-red-600'
                  : 'bg-emerald-600'
              }`}
              initial={false}
              animate={{ width: `${packetProgressPercent}%` }}
              transition={{ duration: 0.45, ease: [0.16, 1, 0.3, 1] }}
            />
          </div>

          {/* Animated Travelling Packet Token on Desktop */}
          <div className="hidden lg:block relative h-10 mb-3">
            <motion.div
              className="absolute top-0 -translate-x-1/2 px-3 py-1.5 rounded-md border text-[11px] font-mono shadow-xs whitespace-nowrap bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 border-slate-700"
              initial={false}
              animate={{ left: `${packetProgressPercent}%` }}
              transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
            >
              {currentStage <= 2 && 'KEY_AGREEMENT (X25519 + ML-KEM-768)'}
              {currentStage === 3 && `HKDF_RATCHET (KeyFP: ${trace?.derivedKeyFingerprint || '...'})`}
              {currentStage === 4 &&
                `AES_256_GCM (CT: ${trace?.originalCiphertextHex.slice(0, 10)}... + 16B Tag)`}
              {currentStage === 5 && `TCP/HTTP_FRAME (${trace?.wirePacketBytes || 0} B on lo0)`}
              {currentStage === 6 &&
                (scenario === 'TAMPER_CIPHERTEXT'
                  ? 'RELAY_FAULT: 1-BIT CIPHERTEXT FLIP!'
                  : scenario === 'TAMPER_HEADER_AAD'
                  ? 'RELAY_FAULT: AAD HEADER NONCE ALTERED!'
                  : scenario === 'REPLAY_DUPLICATE'
                  ? 'RELAY_FAULT: DUPLICATE ENVELOPE REPLAYED!'
                  : 'RELAY_SQLITE: CIPHERTEXT STORED')}
              {currentStage === 7 && 'PACKETGUARD_TAP: METADATA ONLY (0B Plaintext)'}
              {currentStage === 8 &&
                (trace?.bobVerifySuccess
                  ? 'BOB_VERIFIED: GCM TAG OK -> STATE COMMITTED'
                  : `BOB_REJECTED: ${trace?.bobErrorType} (STATE INTACT)`)}
            </motion.div>
          </div>

          {/* 4 Architectural Nodes */}
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 relative z-10">
            {/* Node 1: Alice Endpoint */}
            <motion.div
              animate={{
                scale: activeStageMeta.actorZone === 'ALICE_ENDPOINT' ? 1.015 : 1,
              }}
              transition={{ duration: 0.2 }}
              className={`p-4 rounded-lg border bg-white dark:bg-slate-900 ${
                activeStageMeta.actorZone === 'ALICE_ENDPOINT'
                  ? 'border-slate-900 dark:border-slate-100 ring-1 ring-slate-900 dark:ring-slate-100'
                  : 'border-slate-200 dark:border-slate-800'
              }`}
            >
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="font-bold text-slate-900 dark:text-slate-100">
                  NODE A: ALICE ENDPOINT
                </span>
                <span className="text-slate-500">127.0.0.1:54110</span>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
                Holds Alice’s private keys, derives A2B message keys via HKDF-SHA-256, and seals payload + AAD with AES-256-GCM.
              </p>
              <div className="mt-3 pt-2 border-t border-slate-200 dark:border-slate-800 font-mono text-[11px] tabular-nums space-y-1">
                <div>
                  Chain A2B: E{trace?.epochUsed ?? 0}:M{trace?.msgNumUsed ?? 0}
                </div>
                <div className="truncate text-emerald-700 dark:text-emerald-400">
                  MsgKey FP: {trace?.derivedKeyFingerprint} (Local Only)
                </div>
              </div>
            </motion.div>

            {/* Node 2: Untrusted SQLite Relay */}
            <motion.div
              animate={{
                scale: activeStageMeta.actorZone === 'NETWORK_AND_RELAY' ? 1.015 : 1,
              }}
              transition={{ duration: 0.2 }}
              className={`p-4 rounded-lg border bg-white dark:bg-slate-900 ${
                activeStageMeta.actorZone === 'NETWORK_AND_RELAY'
                  ? scenario === 'TAMPER_CIPHERTEXT' || scenario === 'TAMPER_HEADER_AAD'
                    ? 'border-amber-600 ring-1 ring-amber-600'
                    : 'border-slate-900 dark:border-slate-100 ring-1 ring-slate-900 dark:ring-slate-100'
                  : 'border-slate-200 dark:border-slate-800'
              }`}
            >
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="font-bold text-slate-900 dark:text-slate-100">
                  NODE B: UNTRUSTED RELAY
                </span>
                <span className="text-slate-500">127.0.0.1:3000</span>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
                Routes encrypted envelopes and checks membership. Possesses zero private keys, chain keys, or message keys.
              </p>
              <div className="mt-3 pt-2 border-t border-slate-200 dark:border-slate-800 font-mono text-[11px] tabular-nums space-y-1">
                <div>Plaintext Visibility: 0 Bytes (Opaque Hex)</div>
                <div
                  className={
                    scenario === 'NORMAL_E2EE' || scenario === 'EPOCH_ROLLOVER'
                      ? 'text-slate-600 dark:text-slate-400'
                      : 'text-amber-700 dark:text-amber-400 font-semibold'
                  }
                >
                  Intervention: {scenario}
                </div>
              </div>
            </motion.div>

            {/* Node 3: PacketGuard Passive Tap */}
            <motion.div
              animate={{
                scale: activeStageMeta.actorZone === 'PACKETGUARD_TAP' ? 1.015 : 1,
              }}
              transition={{ duration: 0.2 }}
              className={`p-4 rounded-lg border bg-white dark:bg-slate-900 ${
                activeStageMeta.actorZone === 'PACKETGUARD_TAP'
                  ? 'border-slate-900 dark:border-slate-100 ring-1 ring-slate-900 dark:ring-slate-100'
                  : 'border-slate-200 dark:border-slate-800'
              }`}
            >
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="font-bold text-slate-900 dark:text-slate-100">
                  NODE C: PACKETGUARD TAP
                </span>
                <span className="text-slate-500">Interface: lo0</span>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
                Inspects L2/L3/L4 packet headers (IP, port, TCP flags, byte lengths) and runs sliding-window anomaly heuristics.
              </p>
              <div className="mt-3 pt-2 border-t border-slate-200 dark:border-slate-800 font-mono text-[11px] tabular-nums space-y-1">
                <div>Observed: 3 Loopback Packets (POST + 200 + ACK)</div>
                <div>Wire Size: {trace?.wirePacketBytes ?? 0} Bytes</div>
              </div>
            </motion.div>

            {/* Node 4: Bob Endpoint */}
            <motion.div
              animate={{
                scale: activeStageMeta.actorZone === 'BOB_ENDPOINT' ? 1.015 : 1,
              }}
              transition={{ duration: 0.2 }}
              className={`p-4 rounded-lg border bg-white dark:bg-slate-900 ${
                activeStageMeta.actorZone === 'BOB_ENDPOINT'
                  ? trace?.bobVerifySuccess
                    ? 'border-emerald-600 ring-1 ring-emerald-600'
                    : 'border-red-600 ring-1 ring-red-600'
                  : 'border-slate-200 dark:border-slate-800'
              }`}
            >
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="font-bold text-slate-900 dark:text-slate-100">
                  NODE D: BOB ENDPOINT
                </span>
                <span className="text-slate-500">127.0.0.1:54120</span>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">
                Enforces replay watermark, tentatively derives MessageKey, verifies 128-bit GCM tag, and commits state atomically.
              </p>
              <div className="mt-3 pt-2 border-t border-slate-200 dark:border-slate-800 font-mono text-[11px] tabular-nums space-y-1">
                <div
                  className={
                    trace?.bobVerifySuccess
                      ? 'text-emerald-700 dark:text-emerald-400 font-semibold'
                      : 'text-red-700 dark:text-red-400 font-semibold'
                  }
                >
                  Outcome:{' '}
                  {trace?.bobVerifySuccess
                    ? 'VERIFIED & DECRYPTED'
                    : `REJECTED (${trace?.bobErrorType})`}
                </div>
                <div>
                  Receive Chain: {trace?.bobStateCommitted ? 'ADVANCED (+1)' : 'PRESERVED (ROLLBACK)'}
                </div>
              </div>
            </motion.div>
          </div>
        </div>

        {/* =================================================================== */}
        {/* STAGE-SPECIFIC ANIMATED ALGORITHM & BYTE TRANSFORMATION CANVAS       */}
        {/* =================================================================== */}
        <AnimatePresence mode="wait">
          <motion.div
            key={`${currentStage}-${scenario}`}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.18 }}
            className="p-6 bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 rounded-lg space-y-5"
          >
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 pb-3">
              <div>
                <h2 className="text-base font-bold text-slate-900 dark:text-slate-100">
                  {activeStageMeta.title}
                </h2>
                <p className="text-xs text-slate-600 dark:text-slate-400 mt-0.5">
                  {activeStageMeta.summary}
                </p>
              </div>
              <span className="text-xs font-mono font-semibold text-slate-700 dark:text-slate-300 shrink-0">
                [{activeStageMeta.algorithmBadge}]
              </span>
            </div>

            {/* STAGE 1: HYBRID KEY EXCHANGE */}
            {currentStage === 1 && trace && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 font-mono text-xs tabular-nums">
                <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md space-y-2">
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    1. Classical Elliptic-Curve Diffie-Hellman (X25519)
                  </div>
                  <div className="text-slate-500">
                    Alice Ephemeral Pub (32B):
                    <div className="text-slate-900 dark:text-slate-100 break-all mt-0.5">
                      {trace.aliceX25519PubHex}
                    </div>
                  </div>
                  <div className="text-slate-500">
                    Bob Ephemeral Pub (32B):
                    <div className="text-slate-900 dark:text-slate-100 break-all mt-0.5">
                      {trace.bobX25519PubHex}
                    </div>
                  </div>
                  <div className="pt-2 border-t border-slate-200 dark:border-slate-800 font-sans text-slate-600 dark:text-slate-400">
                    Both compute identical 32-byte <code className="font-mono">DH_SS = X25519(priv, peerPub)</code> over Curve25519.
                  </div>
                </div>

                <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md space-y-2">
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    2. Post-Quantum KEM (NIST FIPS 203 ML-KEM-768)
                  </div>
                  <div className="text-slate-500">
                    Bob ML-KEM-768 Public Key Size:{' '}
                    <span className="text-slate-900 dark:text-slate-100 font-semibold">
                      {trace.bobMlKemPubBytes} Bytes
                    </span>
                  </div>
                  <div className="text-slate-500">
                    Encapsulated KEM Ciphertext (1088 Bytes, sample prefix):
                    <div className="text-slate-900 dark:text-slate-100 break-all mt-0.5">
                      {trace.mlKemCiphertextHex
                        ? `${trace.mlKemCiphertextHex.slice(0, 64)}...`
                        : '(Classical Mode Selected)'}
                    </div>
                  </div>
                  <div className="pt-2 border-t border-slate-200 dark:border-slate-800 font-sans text-slate-600 dark:text-slate-400">
                    Alice encapsulates a 32-byte post-quantum <code className="font-mono">KEM_SS</code>; Bob decapsulates using his 2400-byte lattice secret key.
                  </div>
                </div>

                <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md space-y-2">
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    3. Out-of-Band SHA-256 Safety Fingerprint
                  </div>
                  <div className="text-slate-500">
                    Transcript Input:
                    <div className="text-slate-800 dark:text-slate-200 break-all mt-0.5">
                      ARX-SAFETY-FP-V1|{trace.mode}|{trace.sessionId}|alicePub|bobPub|mlKemPub
                    </div>
                  </div>
                  <div className="p-2.5 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 rounded text-emerald-800 dark:text-emerald-300 font-semibold text-center">
                    {trace.safetyFingerprint}
                  </div>
                  <div className="font-sans text-slate-600 dark:text-slate-400">
                    Comparing this 30-char fingerprint detects any active MITM public-key replacement on the relay.
                  </div>
                </div>
              </div>
            )}

            {/* STAGE 2: ROOT & EPOCH KDF */}
            {currentStage === 2 && trace && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 font-mono text-xs tabular-nums">
                <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md space-y-2">
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    1. Input Keying Material (IKM) &amp; Transcript Salt
                  </div>
                  <div className="text-slate-600 dark:text-slate-400">
                    IKM = <span className="text-slate-900 dark:text-slate-100">DH_SS (32B) || KEM_SS (32B)</span> = 64 Bytes
                  </div>
                  <div className="text-slate-600 dark:text-slate-400">
                    Salt = <span className="text-slate-900 dark:text-slate-100">SHA256(Protocol || SessionID || PubKeys || KEM_CT_Hash)</span>
                  </div>
                  <div className="pt-2 border-t border-slate-200 dark:border-slate-800 font-sans text-slate-600 dark:text-slate-400">
                    Binding the full handshake transcript into HKDF-Extract guarantees context separation.
                  </div>
                </div>

                <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md space-y-2">
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    2. Epoch State &amp; Rollover Check
                  </div>
                  <div>
                    Configured Epoch Size: <span className="font-semibold">{epochSize} messages / epoch</span>
                  </div>
                  <div>
                    Counter Before Message: <span className="font-semibold">Epoch {trace.epochBefore}, Msg #{trace.msgNumBefore}</span>
                  </div>
                  <div
                    className={`p-2 rounded border ${
                      trace.epochRolloverOccurred
                        ? 'bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800 text-amber-800 dark:text-amber-300 font-semibold'
                        : 'bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700'
                    }`}
                  >
                    {trace.epochRolloverOccurred
                      ? `EPOCH BOUNDARY REACHED (${trace.msgNumBefore} >= ${epochSize})! Ratcheted Epoch ${trace.epochBefore} -> Epoch ${trace.epochUsed} and reset Msg #0.`
                      : `Within Epoch ${trace.epochUsed} (${trace.msgNumUsed} < ${epochSize}). Using current Epoch chain.`}
                  </div>
                </div>

                <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md space-y-2">
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    3. Domain-Separated Directional Chains
                  </div>
                  <div className="text-slate-500">
                    Info A2B: <code className="text-slate-800 dark:text-slate-200">ARX-DIRECTION-CHAIN|...|dir=A2B|epoch={trace.epochUsed}</code>
                  </div>
                  <div className="text-slate-500">
                    Info B2A: <code className="text-slate-800 dark:text-slate-200">ARX-DIRECTION-CHAIN|...|dir=B2A|epoch={trace.epochUsed}</code>
                  </div>
                  <div className="pt-2 border-t border-slate-200 dark:border-slate-800 font-sans text-slate-600 dark:text-slate-400">
                    Alice’s sending chain (<code className="font-mono">A2B</code>) and Bob’s sending chain (<code className="font-mono">B2A</code>) are cryptographically independent.
                  </div>
                </div>
              </div>
            )}

            {/* STAGE 3: ONE-WAY PER-MESSAGE KDF RATCHET */}
            {currentStage === 3 && trace && (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-center font-mono text-xs tabular-nums">
                <div className="lg:col-span-4 p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md space-y-2">
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    Input: Current ChainKey_A2B (32 Bytes)
                  </div>
                  <div className="p-2 bg-slate-100 dark:bg-slate-800 rounded break-all text-[11px]">
                    {trace.chainKeyBeforeHex}
                  </div>
                  <div className="text-slate-500 font-sans">
                    Context Bound Info:
                    <div className="font-mono text-[11px] text-slate-800 dark:text-slate-200 break-all mt-0.5">
                      ARX-MSG-KDF|v1|proto={trace.protocolVersion}|sid={trace.sessionId}|from=alice|to=bob|dir=A2B|epoch={trace.epochUsed}|msg={trace.msgNumUsed}
                    </div>
                  </div>
                </div>

                <div className="lg:col-span-3 p-4 bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 rounded-md text-center space-y-2">
                  <div className="font-sans font-bold text-sm">
                    HKDF-SHA-256 Ratchet
                  </div>
                  <div className="text-[11px] opacity-80">
                    One-Way PRF Expansion
                  </div>
                  <div className="py-1 px-2 bg-white/10 dark:bg-slate-900/10 rounded text-[11px]">
                    76 Bytes Output Keying Material (OKM)
                  </div>
                  <div className="font-sans text-[11px] opacity-90">
                    Previous ChainKey is immediately overwritten
                  </div>
                </div>

                <div className="lg:col-span-5 p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md space-y-2.5">
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    3 Sliced Ratchet Outputs (Bytes 0..75):
                  </div>
                  <div>
                    <span className="text-slate-500">1. NextChainKey [0..31] (32B): </span>
                    <div className="text-slate-900 dark:text-slate-100 break-all text-[11px]">
                      {trace.nextChainKeyHex}
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-500">2. Ephemeral MessageKey [32..63] (32B / 256-bit): </span>
                    <div className="text-emerald-700 dark:text-emerald-400 break-all text-[11px] font-semibold">
                      {trace.derivedMessageKeyHex} (Teaching FP: {trace.derivedKeyFingerprint})
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-500">3. Derived Nonce / IV [64..75] (12B / 96-bit): </span>
                    <div className="text-sky-700 dark:text-sky-400 break-all text-[11px] font-semibold">
                      {trace.derivedNonceHex}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* STAGE 4: CANONICAL AAD & AES-256-GCM AUTHENTICATED ENCRYPTION */}
            {currentStage === 4 && trace && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 font-mono text-xs tabular-nums">
                <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md space-y-2">
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    1. Plaintext &amp; Deterministic Canonical AAD
                  </div>
                  <div>
                    <span className="text-slate-500 font-sans">Plaintext ({trace.plaintextBytes} B): </span>
                    <div className="p-2 mt-0.5 bg-slate-100 dark:bg-slate-800 rounded text-slate-900 dark:text-slate-100 font-sans">
                      &ldquo;{trace.plaintext}&rdquo;
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-500 font-sans">UTF-8 Plaintext Hex: </span>
                    <div className="text-[11px] break-all text-slate-700 dark:text-slate-300">
                      {trace.plaintextHex}
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-500 font-sans">Canonical AAD Header String: </span>
                    <div className="p-2 mt-0.5 bg-slate-100 dark:bg-slate-800 rounded text-[11px] break-all">
                      {trace.canonicalAadString}
                    </div>
                  </div>
                </div>

                <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md space-y-2">
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    2. AES-256-GCM AEAD Construction
                  </div>
                  <div className="font-sans text-slate-600 dark:text-slate-400 space-y-1.5">
                    <p>
                      • <strong>Confidentiality (AES-256-CTR):</strong> Encrypts the {trace.plaintextBytes}-byte UTF-8 payload using the 256-bit <code className="font-mono">MessageKey</code> and 96-bit <code className="font-mono">Nonce</code>.
                    </p>
                    <p>
                      • <strong>Integrity &amp; Header Binding (GHASH):</strong> Computes a 128-bit polynomial authentication tag over both the <strong>Canonical AAD bytes</strong> and the <strong>Ciphertext bytes</strong>.
                    </p>
                  </div>
                </div>

                <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md space-y-2">
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    3. Sealed Output (Ciphertext + 16B Tag Split)
                  </div>
                  <div>
                    <span className="text-slate-500">Raw Ciphertext ({trace.plaintextBytes} B): </span>
                    <div className="p-2 mt-0.5 bg-slate-100 dark:bg-slate-800 rounded break-all text-[11px]">
                      {trace.originalCiphertextHex}
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-500">128-Bit GCM Authentication Tag (16 B): </span>
                    <div className="p-2 mt-0.5 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 rounded text-emerald-800 dark:text-emerald-300 font-semibold break-all text-[11px]">
                      {trace.originalAuthTagHex}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* STAGE 5: NETWORK PACKET FRAMING */}
            {currentStage === 5 && trace && (
              <div className="space-y-4">
                <div className="font-sans text-xs font-semibold text-slate-900 dark:text-slate-100">
                  Layered Network Encapsulation (Why 1 Application Message = {trace.wirePacketBytes} Wire Bytes in Packet #1 + 2 Ack Packets):
                </div>
                <div className="grid grid-cols-1 md:grid-cols-5 gap-2 font-mono text-xs tabular-nums">
                  <div className="p-3 bg-slate-200 dark:bg-slate-800 rounded border border-slate-300 dark:border-slate-700">
                    <div className="font-bold">L1/L2: Loopback (lo0)</div>
                    <div className="text-[11px] text-slate-600 dark:text-slate-400 mt-1">
                      +4 Bytes Null/Loopback family header
                    </div>
                  </div>
                  <div className="p-3 bg-slate-100 dark:bg-slate-800/70 rounded border border-slate-300 dark:border-slate-700">
                    <div className="font-bold">L3: IPv4 Header</div>
                    <div className="text-[11px] text-slate-600 dark:text-slate-400 mt-1">
                      +20 Bytes (127.0.0.1 → 127.0.0.1)
                    </div>
                  </div>
                  <div className="p-3 bg-sky-50 dark:bg-sky-950/40 rounded border border-sky-200 dark:border-sky-800">
                    <div className="font-bold text-sky-900 dark:text-sky-200">
                      L4: TCP Segment
                    </div>
                    <div className="text-[11px] text-sky-700 dark:text-sky-300 mt-1">
                      +20 Bytes (:54110 → :3000, Flags: [PSH,ACK])
                    </div>
                  </div>
                  <div className="p-3 bg-indigo-50 dark:bg-indigo-950/40 rounded border border-indigo-200 dark:border-indigo-800">
                    <div className="font-bold text-indigo-900 dark:text-indigo-200">
                      L7: HTTP POST Header
                    </div>
                    <div className="text-[11px] text-indigo-700 dark:text-indigo-300 mt-1">
                      +218 Bytes (POST /api/relay/send)
                    </div>
                  </div>
                  <div className="p-3 bg-emerald-50 dark:bg-emerald-950/40 rounded border border-emerald-200 dark:border-emerald-800">
                    <div className="font-bold text-emerald-900 dark:text-emerald-200">
                      ARX JSON Envelope
                    </div>
                    <div className="text-[11px] text-emerald-700 dark:text-emerald-300 mt-1">
                      {trace.serializedEnvelopeBytes} Bytes ( includes 28B raw crypto + hex/JSON)
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* STAGE 6: UNTRUSTED SQLITE RELAY & FAULT INJECTION */}
            {currentStage === 6 && trace && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 font-mono text-xs tabular-nums">
                <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md space-y-2">
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    Envelope Entering Relay (:3000) from Alice
                  </div>
                  <div>
                    <span className="text-slate-500">Original Header Nonce: </span>
                    <span>{trace.derivedNonceHex}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Original Ciphertext Hex: </span>
                    <div className="p-2 mt-0.5 bg-slate-100 dark:bg-slate-800 rounded break-all text-[11px]">
                      {trace.originalCiphertextHex}
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-500">Original 128-bit GCM Tag: </span>
                    <span className="text-emerald-700 dark:text-emerald-400">
                      {trace.originalAuthTagHex}
                    </span>
                  </div>
                </div>

                <div
                  className={`p-4 rounded-md border space-y-2 ${
                    scenario === 'TAMPER_CIPHERTEXT' ||
                    scenario === 'TAMPER_HEADER_AAD' ||
                    scenario === 'REPLAY_DUPLICATE'
                      ? 'bg-amber-50/70 dark:bg-amber-950/30 border-amber-400 dark:border-amber-700'
                      : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800'
                  }`}
                >
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    Envelope Leaving Relay Toward Bob ({scenario})
                  </div>
                  <div>
                    <span className="text-slate-500">Transmitted Header Nonce: </span>
                    <span
                      className={
                        scenario === 'TAMPER_HEADER_AAD'
                          ? 'text-red-700 dark:text-red-400 font-bold underline'
                          : ''
                      }
                    >
                      {trace.transmittedNonceHex}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500">Transmitted Ciphertext Hex: </span>
                    <div
                      className={`p-2 mt-0.5 rounded break-all text-[11px] ${
                        scenario === 'TAMPER_CIPHERTEXT'
                          ? 'bg-red-100 dark:bg-red-950/60 text-red-800 dark:text-red-200 font-bold'
                          : 'bg-slate-100 dark:bg-slate-800'
                      }`}
                    >
                      {trace.transmittedCiphertextHex}
                    </div>
                  </div>
                  <div className="font-sans text-xs pt-1 text-slate-700 dark:text-slate-300">
                    {scenario === 'TAMPER_CIPHERTEXT' &&
                      'Active Attack: Relay flipped 1 bit in the middle byte of ciphertextHex (`byte ^= 0x01`), but cannot recompute the 128-bit GCM tag without Alice’s 256-bit MessageKey!'}
                    {scenario === 'TAMPER_HEADER_AAD' &&
                      'Active Attack: Relay modified the first byte of header.nonceHex (`nonce[0] ^= 0xff`), altering the canonical AAD string without knowing the 256-bit MessageKey!'}
                    {scenario === 'REPLAY_DUPLICATE' &&
                      'Active Attack: Relay re-transmitted an exact copy of an envelope that Bob already verified and accepted earlier!'}
                    {(scenario === 'NORMAL_E2EE' || scenario === 'EPOCH_ROLLOVER') &&
                      'Honest Relay Operation: Envelope stored in SQLite (`relay_envelopes`) and forwarded bit-for-bit without modification.'}
                  </div>
                </div>
              </div>
            )}

            {/* STAGE 7: PACKETGUARD PASSIVE TAP */}
            {currentStage === 7 && trace && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 font-mono text-xs tabular-nums">
                <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md space-y-2">
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    What PacketGuard Sees on the Wire (Metadata Only)
                  </div>
                  <div>Source / Dest IP: 127.0.0.1:54110 → 127.0.0.1:3000</div>
                  <div>Protocol &amp; Flags: TCP / HTTP [PSH,ACK]</div>
                  <div>Captured Frame Size: {trace.wirePacketBytes} Bytes</div>
                  <div>Payload Entropy: High (Indistinguishable from random uniform bytes)</div>
                  <div className="text-emerald-700 dark:text-emerald-400 font-sans font-medium pt-1">
                    Plaintext Exposure to Network Sniffer: 0 Bytes
                  </div>
                </div>

                <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md space-y-2">
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    Reusable Metadata-Only Heuristic Rule Evaluation
                  </div>
                  <ul className="font-sans text-xs text-slate-600 dark:text-slate-400 space-y-1 list-disc list-inside">
                    <li>
                      <strong>Port Scan Rule:</strong> Counts distinct destination ports per <code className="font-mono">(srcIp, dstIp)</code> in sliding 10s window.
                    </li>
                    <li>
                      <strong>SYN Flood Rule:</strong> Correlates 4-tuple <code className="font-mono">SYN → SYN,ACK → ACK</code> handshakes (ignores uncorrelated ACKs).
                    </li>
                    <li>
                      <strong>ARP Conflict Rule:</strong> Detects multiple hardware MAC addresses claiming 1 IPv4 address.
                    </li>
                    <li>
                      <strong>DNS Heuristic Rule:</strong> Computes Shannon entropy <code className="font-mono">-∑ p(x) log2 p(x)</code> and label length on DNS queries.
                    </li>
                  </ul>
                </div>
              </div>
            )}

            {/* STAGE 8: BOB ENDPOINT VERIFICATION & ATOMIC COMMIT */}
            {currentStage === 8 && trace && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 font-mono text-xs tabular-nums">
                <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md space-y-2">
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    1. Replay Watermark &amp; Tentative KDF
                  </div>
                  <div>
                    Record ID: <span className="font-semibold">epoch={trace.epochUsed}, msg={trace.msgNumUsed}</span>
                  </div>
                  <div
                    className={
                      scenario === 'REPLAY_DUPLICATE'
                        ? 'text-red-700 dark:text-red-400 font-bold'
                        : 'text-emerald-700 dark:text-emerald-400'
                    }
                  >
                    Seen-Key Lookup:{' '}
                    {scenario === 'REPLAY_DUPLICATE'
                      ? 'FOUND IN seenMessageKeys -> REPLAY_DETECTED!'
                      : 'Not seen previously -> Proceed to tentative KDF'}
                  </div>
                  <div className="font-sans text-slate-600 dark:text-slate-400 pt-1">
                    Bob computes candidate <code className="font-mono">MessageKey</code> in temporary memory without mutating <code className="font-mono">recvChainKey</code> yet.
                  </div>
                </div>

                <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-md space-y-2">
                  <div className="font-sans font-semibold text-slate-900 dark:text-slate-100">
                    2. AES-256-GCM Tag &amp; AAD Check
                  </div>
                  <div>
                    <span className="text-slate-500">Transmitted Tag: </span>
                    <div className="text-[11px] break-all">{trace.transmittedAuthTagHex}</div>
                  </div>
                  <div>
                    <span className="text-slate-500">Expected Tag over Transmitted (AAD + CT): </span>
                    <div
                      className={`text-[11px] break-all font-semibold ${
                        trace.transmittedAuthTagHex === trace.recomputedExpectedTagHex
                          ? 'text-emerald-700 dark:text-emerald-400'
                          : 'text-red-700 dark:text-red-400'
                      }`}
                    >
                      {trace.recomputedExpectedTagHex}
                    </div>
                  </div>
                </div>

                <div
                  className={`p-4 rounded-md border space-y-2 ${
                    trace.bobVerifySuccess
                      ? 'bg-emerald-50/70 dark:bg-emerald-950/30 border-emerald-400 dark:border-emerald-800'
                      : 'bg-red-50/70 dark:bg-red-950/30 border-red-400 dark:border-red-800'
                  }`}
                >
                  <div className="font-sans font-bold text-slate-900 dark:text-slate-100">
                    3. Final Endpoint Decision &amp; State Commit
                  </div>
                  {trace.bobVerifySuccess ? (
                    <>
                      <div className="text-emerald-800 dark:text-emerald-300 font-semibold">
                        STATUS: VERIFIED (AES-256-GCM Authentic)
                      </div>
                      <div className="p-2 bg-white dark:bg-slate-900 rounded border border-emerald-200 dark:border-emerald-800 font-sans text-slate-900 dark:text-slate-100">
                        Decrypted Plaintext: &ldquo;{trace.bobDecryptedPlaintext}&rdquo;
                      </div>
                      <div className="font-sans text-slate-600 dark:text-slate-400">
                        Atomic Commit: <code className="font-mono">recvChainKey</code> advanced and <code className="font-mono">{trace.epochUsed}:{trace.msgNumUsed}</code> recorded in <code className="font-mono">seenMessageKeys</code>.
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="text-red-800 dark:text-red-300 font-semibold">
                        STATUS: REJECTED ({trace.bobErrorType})
                      </div>
                      <div className="font-sans text-red-700 dark:text-red-300">
                        {trace.bobErrorMessage}
                      </div>
                      <div className="font-sans text-slate-700 dark:text-slate-300">
                        <strong>Atomic Rollback:</strong> Zero corrupted plaintext released. Bob’s <code className="font-mono">recvChainKey</code> and <code className="font-mono">recvMsgNum</code> remain untouched so the next legitimate message succeeds!
                      </div>
                    </>
                  )}
                </div>
              </div>
            )}
          </motion.div>
        </AnimatePresence>
      </div>

      {/* Floating Animated Control Deck (Always Visible Anywhere on the Visual Flow Page) */}
      <aside
        aria-label="Floating visual flow controls"
        className="fixed bottom-6 right-6 z-40 flex items-center gap-2 p-2 rounded-full backdrop-blur-xl transition-all duration-300 shadow-2xl bg-slate-900/95 text-white border-2 border-indigo-500/80 shadow-indigo-950/50 ring-2 ring-indigo-500/20 dark:bg-slate-950/95 dark:text-cyan-50 dark:border-2 dark:border-cyan-400 dark:shadow-[0_0_35px_rgba(6,182,212,0.55),0_12px_28px_rgba(0,0,0,0.85)] dark:ring-4 dark:ring-cyan-500/30"
      >
        <button
          type="button"
          onClick={() => {
            setIsPlaying(false);
            setCurrentStage((s) => Math.max(1, s - 1));
          }}
          disabled={currentStage <= 1}
          title="Previous Stage (← Left Arrow)"
          aria-label="Previous Stage"
          className="p-2.5 rounded-full hover:bg-white/15 dark:hover:bg-cyan-500/20 text-slate-200 dark:text-cyan-300 hover:text-white dark:hover:text-cyan-100 disabled:opacity-25 disabled:cursor-not-allowed transition-all"
        >
          <ChevronLeft className="w-5 h-5" />
        </button>

        <button
          type="button"
          onClick={() => {
            if (currentStage >= 8) setCurrentStage(1);
            setIsPlaying((p) => !p);
          }}
          title={isPlaying ? 'Pause Animation (Space)' : currentStage >= 8 ? 'Replay Animation (Space)' : 'Play Animation (Space)'}
          aria-label={isPlaying ? 'Pause' : 'Play'}
          className={`p-2.5 rounded-full font-bold transition-all transform active:scale-95 shadow-md ${
            isPlaying
              ? 'bg-amber-500 hover:bg-amber-400 text-slate-950 shadow-amber-500/40 dark:bg-amber-400 dark:hover:bg-amber-300 dark:shadow-[0_0_20px_rgba(251,191,36,0.8)]'
              : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950 shadow-emerald-500/40 dark:bg-cyan-400 dark:hover:bg-cyan-300 dark:shadow-[0_0_20px_rgba(34,211,238,0.85)]'
          }`}
        >
          {isPlaying ? <Pause className="w-5 h-5" /> : <Play className="w-5 h-5 ml-0.5" />}
        </button>

        <button
          type="button"
          onClick={() => {
            setIsPlaying(false);
            setCurrentStage((s) => Math.min(8, s + 1));
          }}
          disabled={currentStage >= 8}
          title="Next Stage (→ Right Arrow)"
          aria-label="Next Stage"
          className="p-2.5 rounded-full hover:bg-white/15 dark:hover:bg-cyan-500/20 text-slate-200 dark:text-cyan-300 hover:text-white dark:hover:text-cyan-100 disabled:opacity-25 disabled:cursor-not-allowed transition-all"
        >
          <ChevronRight className="w-5 h-5" />
        </button>

        <div className="h-5 w-px bg-white/20 dark:bg-cyan-500/40 mx-1" />

        {/* Stage Progress Indicator with Live Pulsing Beacon */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-mono tabular-nums bg-white/10 dark:bg-cyan-950/80 border border-white/10 dark:border-cyan-400/50 text-white dark:text-cyan-200 shadow-inner">
          {isPlaying ? (
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 dark:bg-cyan-400 opacity-80" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400 dark:bg-cyan-300" />
            </span>
          ) : (
            <span className="inline-flex rounded-full h-2 w-2 bg-slate-400 dark:bg-cyan-700" />
          )}
          <span className="font-bold text-emerald-400 dark:text-cyan-300">
            {currentStage}
          </span>
          <span className="opacity-50">/8</span>
          <span className="hidden sm:inline text-[11px] opacity-80 max-w-[130px] truncate ml-0.5">
            {activeStageMeta.shortTitle}
          </span>
        </div>

        {/* Speed Quick-Toggle */}
        <button
          type="button"
          onClick={() => {
            setStepIntervalMs((current) =>
              current === 2600 ? 1500 : current === 1500 ? 3600 : 2600
            );
          }}
          title={`Animation Speed: ${
            stepIntervalMs === 1500
              ? '1.75x Fast (click for 0.75x)'
              : stepIntervalMs === 3600
              ? '0.75x Detailed (click for 1.0x)'
              : '1.0x Normal (click for 1.75x)'
          }`}
          aria-label="Toggle Animation Speed"
          className="px-2 py-1 text-[11px] font-mono font-bold rounded-full bg-white/10 hover:bg-white/20 dark:bg-cyan-900/40 dark:hover:bg-cyan-800/60 dark:text-cyan-300 text-slate-200 border border-white/10 dark:border-cyan-500/40 transition-all"
        >
          {stepIntervalMs === 1500 ? '1.75x' : stepIntervalMs === 3600 ? '0.75x' : '1.0x'}
        </button>

        <button
          type="button"
          onClick={() => {
            setIsPlaying(false);
            setCurrentStage(1);
          }}
          title="Reset to Stage 1"
          aria-label="Reset to Stage 1"
          className="p-2.5 rounded-full hover:bg-white/15 dark:hover:bg-cyan-500/20 transition-all text-slate-400 dark:text-cyan-400/70 hover:text-white dark:hover:text-cyan-200"
        >
          <RotateCcw className="w-4 h-4" />
        </button>
      </aside>
    </div>
  );
};
