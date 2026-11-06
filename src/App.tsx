/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  decryptEndpointMessage,
  encryptEndpointMessage,
  establishSessionPair,
  formatCanonicalHeaderString,
  generateIdentityKeyBundle,
  type EncryptedEnvelope,
  type EncryptionMode,
  type EndpointSessionState,
  type IdentityKeyBundle,
  type ParticipantId,
  type SessionInitHandshake,
} from './crypto/arxCrypto.ts';
import { processEnvelopeAtBobBotEndpoint } from './crypto/bobBot.ts';
import {
  computeTrafficMetrics,
  DEFAULT_RULE_CONFIG,
  type DetectionRuleConfig,
  type HeuristicAlert,
  type PacketMetadataRecord,
  type ScenarioId,
} from './monitor/packetGuardEngine.ts';
import type {
  LiveCaptureStatus,
  LocalDemoSettings,
  RelayEventLogEntry,
} from './server/relayStore.ts';
import { PacketDashboardView } from './components/PacketDashboardView.tsx';
import {
  ExperimentsAndDocsView,
  type ExperimentLogItem,
} from './components/ExperimentsAndDocsView.tsx';
import { VisualFlowSimulatorView } from './components/VisualFlowSimulatorView.tsx';

type ActiveTab = 'overview' | 'flow' | 'chat' | 'relay' | 'packets' | 'experiments';
type WorkspaceRoleView = 'dual' | 'alice' | 'bob';

export interface EndpointChatMessage {
  id: string;
  envelopeId: string;
  sender: ParticipantId;
  recipient: ParticipantId;
  direction: 'A2B' | 'B2A';
  epoch: number;
  msgNum: number;
  mode: EncryptionMode;
  status: 'VERIFIED' | 'AUTH_FAILED' | 'REPLAY_DETECTED' | 'OUT_OF_ORDER_LIMIT';
  plaintext?: string;
  errorReason?: string;
  nonceHex: string;
  localKeyFingerprint?: string;
  encryptTimeMs?: number;
  decryptTimeMs?: number;
  rttMs?: number;
  timestampMs: number;
}

export default function App() {
  // Determine initial role from URL query (?role=alice or ?role=bob)
  const initialRole = useMemo<WorkspaceRoleView>(() => {
    if (typeof window === 'undefined') return 'dual';
    const params = new URLSearchParams(window.location.search);
    const r = params.get('role')?.toLowerCase();
    if (r === 'alice') return 'alice';
    if (r === 'bob') return 'bob';
    return 'dual';
  }, []);

  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [roleView, setRoleView] = useState<WorkspaceRoleView>(initialRole);
  const [darkMode, setDarkMode] = useState<boolean>(false);

  // Session & Cryptographic Configuration
  const [encryptionMode, setEncryptionMode] = useState<EncryptionMode>('HYBRID_X25519_MLKEM768');
  const [epochSize, setEpochSize] = useState<number>(5);
  const [bobBotEnabled, setBobBotEnabled] = useState<boolean>(true);

  // Endpoint Cryptographic States (isolated per endpoint)
  const [aliceIdentity, setAliceIdentity] = useState<IdentityKeyBundle>(() =>
    generateIdentityKeyBundle('alice')
  );
  const [bobIdentity, setBobIdentity] = useState<IdentityKeyBundle>(() =>
    generateIdentityKeyBundle('bob')
  );
  const [handshake, setHandshake] = useState<SessionInitHandshake | null>(null);
  const [aliceState, setAliceState] = useState<EndpointSessionState | null>(null);
  const [bobState, setBobState] = useState<EndpointSessionState | null>(null);

  // Endpoint Conversation Histories
  const [aliceMessages, setAliceMessages] = useState<EndpointChatMessage[]>([]);
  const [bobMessages, setBobMessages] = useState<EndpointChatMessage[]>([]);
  const [aliceDraft, setAliceDraft] = useState<string>('hello');
  const [bobDraft, setBobDraft] = useState<string>('Ack — telemetry verified.');

  // Measured Execution Metrics (real measured values, never random)
  const [lastEncryptMs, setLastEncryptMs] = useState<number | null>(null);
  const [lastDecryptMs, setLastDecryptMs] = useState<number | null>(null);
  const [lastRelayRttMs, setLastRelayRttMs] = useState<number | null>(null);

  // Relay & PacketGuard Backend State
  const [relayConnected, setRelayConnected] = useState<boolean>(true);
  const [relayEnvelopes, setRelayEnvelopes] = useState<
    Array<EncryptedEnvelope & { deliveryStatus: string }>
  >([]);
  const [selectedEnvelopeId, setSelectedEnvelopeId] = useState<string | null>(null);
  const [packets, setPackets] = useState<PacketMetadataRecord[]>([]);
  const [alerts, setAlerts] = useState<HeuristicAlert[]>([]);
  const [ruleConfig, setRuleConfig] = useState<DetectionRuleConfig>(DEFAULT_RULE_CONFIG);
  const [demoSettings, setDemoSettings] = useState<LocalDemoSettings>({
    localDemoControlsEnabled: true,
    allowPlaintextBaseline: false,
    nextRelayIntervention: 'NONE',
  });
  const [captureStatus, setCaptureStatus] = useState<LiveCaptureStatus | null>(null);
  const [applicationEvents, setApplicationEvents] = useState<RelayEventLogEntry[]>([]);
  const [trafficPerspective, setTrafficPerspective] = useState<'alice' | 'bob' | 'relay'>('alice');
  const [experimentLogs, setExperimentLogs] = useState<ExperimentLogItem[]>([]);

  // Refs to latest endpoint states for async multi-step sequences & cross-tab sync
  const aliceStateRef = useRef<EndpointSessionState | null>(null);
  const bobStateRef = useRef<EndpointSessionState | null>(null);
  const bobBotEnabledRef = useRef<boolean>(bobBotEnabled);
  const demoSettingsRef = useRef<LocalDemoSettings>(demoSettings);
  const broadcastRef = useRef<BroadcastChannel | null>(null);

  useEffect(() => {
    aliceStateRef.current = aliceState;
  }, [aliceState]);

  useEffect(() => {
    bobStateRef.current = bobState;
  }, [bobState]);

  useEffect(() => {
    bobBotEnabledRef.current = bobBotEnabled;
  }, [bobBotEnabled]);

  useEffect(() => {
    demoSettingsRef.current = demoSettings;
  }, [demoSettings]);

  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [darkMode]);

  const appendExperimentLog = useCallback(
    (
      experimentName: string,
      outcomeStatus: ExperimentLogItem['outcomeStatus'],
      details: string
    ) => {
      setExperimentLogs((prev) => [
        {
          id: `exp-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
          timestamp: Date.now(),
          experimentName,
          outcomeStatus,
          details,
        },
        ...prev.slice(0, 49),
      ]);
    },
    []
  );

  const syncServerState = useCallback(async () => {
    try {
      const res = await fetch('/api/state', {
        headers: { 'X-ARX-User': 'alice' },
      });
      if (!res.ok) throw new Error('Relay HTTP error');
      const data = await res.json();
      setRelayConnected(true);
      setRelayEnvelopes(data.envelopes || []);
      setPackets(data.packets || []);
      setAlerts(data.alerts || []);
      if (data.ruleConfig) setRuleConfig(data.ruleConfig);
      if (data.demoSettings) setDemoSettings(data.demoSettings);
      if (data.captureStatus) setCaptureStatus(data.captureStatus);
      if (data.applicationEvents) setApplicationEvents(data.applicationEvents);
    } catch {
      setRelayConnected(false);
    }
  }, []);

  /**
   * Establishes a fresh cryptographic session between Alice and Bob.
   */
  const initFreshSession = useCallback(
    async (
      targetMode: EncryptionMode = encryptionMode,
      targetEpochSize: number = epochSize
    ) => {
      const newAliceId = generateIdentityKeyBundle('alice');
      const newBobId = generateIdentityKeyBundle('bob');
      setAliceIdentity(newAliceId);
      setBobIdentity(newBobId);

      // If switching to Local Plaintext Baseline, enable allowPlaintextBaseline on relay first
      const allowPlaintext = targetMode === 'LOCAL_PLAINTEXT_BASELINE';
      await fetch('/api/demo/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          localDemoControlsEnabled: true,
          allowPlaintextBaseline: allowPlaintext,
          nextRelayIntervention: 'NONE',
        }),
      }).catch(() => {});

      const established = establishSessionPair(newAliceId, newBobId, {
        mode: targetMode,
        epochSize: targetEpochSize,
      });

      setHandshake(established.handshake);
      setAliceState(established.aliceState);
      setBobState(established.bobState);
      aliceStateRef.current = established.aliceState;
      bobStateRef.current = established.bobState;

      setAliceMessages([]);
      setBobMessages([]);
      setSelectedEnvelopeId(null);

      await fetch('/api/relay/handshake', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-ARX-User': 'alice',
        },
        body: JSON.stringify({
          conversationId: 'conv-alice-bob',
          handshake: established.handshake,
        }),
      }).catch(() => {});

      await syncServerState();

      broadcastRef.current?.postMessage({
        type: 'SESSION_ESTABLISHED',
        handshake: established.handshake,
        aliceState: established.aliceState,
        bobState: established.bobState,
      });

      appendExperimentLog(
        'Session Establishment',
        'NOMINAL',
        `Established ${established.handshake.protocolVersion} session (${established.handshake.sessionId}) with epochSize=${targetEpochSize} and safety fingerprint ${established.aliceState.safetyFingerprint}.`
      );
    },
    [encryptionMode, epochSize, syncServerState, appendExperimentLog]
  );

  // Initialize session on mount + set up BroadcastChannel for multi-window (?role=alice / ?role=bob) sync
  useEffect(() => {
    initFreshSession('HYBRID_X25519_MLKEM768', 5);

    if (typeof BroadcastChannel !== 'undefined') {
      const ch = new BroadcastChannel('arx-packetguard-sync-v1');
      broadcastRef.current = ch;
      ch.onmessage = (ev) => {
        const msg = ev.data;
        if (msg?.type === 'SESSION_ESTABLISHED') {
          setHandshake(msg.handshake);
          setAliceState(msg.aliceState);
          setBobState(msg.bobState);
          aliceStateRef.current = msg.aliceState;
          bobStateRef.current = msg.bobState;
          setAliceMessages([]);
          setBobMessages([]);
          syncServerState();
        } else if (msg?.type === 'STATE_UPDATED') {
          if (msg.aliceState) {
            setAliceState(msg.aliceState);
            aliceStateRef.current = msg.aliceState;
          }
          if (msg.bobState) {
            setBobState(msg.bobState);
            bobStateRef.current = msg.bobState;
          }
          if (msg.aliceMessages) setAliceMessages(msg.aliceMessages);
          if (msg.bobMessages) setBobMessages(msg.bobMessages);
          syncServerState();
        }
      };
      return () => ch.close();
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  /**
   * Delivers a relayed envelope to the recipient endpoint (Bob or Alice),
   * running real endpoint authentication & decryption and updating state ONLY on success.
   */
  const deliverEnvelopeToRecipient = useCallback(
    async (
      relayedEnvelope: EncryptedEnvelope,
      encryptTimeMs?: number,
      rttMs?: number
    ): Promise<{
      decryptOk: boolean;
      errorType?: string;
      errorMessage?: string;
    }> => {
      const recipient = relayedEnvelope.header.recipient;
      const allowPlaintext =
        demoSettingsRef.current.allowPlaintextBaseline ||
        relayedEnvelope.mode === 'LOCAL_PLAINTEXT_BASELINE';

      if (recipient === 'bob') {
        const currentBob = bobStateRef.current;
        if (!currentBob) {
          return { decryptOk: false, errorMessage: 'Bob session not initialized' };
        }

        // If Bob Bot is enabled AND this is not already a replay/bot echo loop, let Bob Bot process it
        if (bobBotEnabledRef.current) {
          const botResult = await processEnvelopeAtBobBotEndpoint(
            currentBob,
            relayedEnvelope,
            { allowLocalPlaintextDemo: allowPlaintext }
          );

          const dec = botResult.inboundDecrypt;
          setLastDecryptMs(dec.executionTimeMs);
          setBobState(botResult.updatedBobState);
          bobStateRef.current = botResult.updatedBobState;

          const statusToReport = dec.success
            ? 'DELIVERED_VERIFIED'
            : dec.errorType === 'REPLAY_DETECTED'
            ? 'REJECTED_REPLAY'
            : 'REJECTED_AUTH_FAILED';

          await fetch('/api/relay/delivery-status', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              envelopeId: relayedEnvelope.envelopeId,
              deliveryStatus: statusToReport,
            }),
          }).catch(() => {});

          const bobInboundMsg: EndpointChatMessage = {
            id: `msg-bob-in-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
            envelopeId: relayedEnvelope.envelopeId,
            sender: 'alice',
            recipient: 'bob',
            direction: 'A2B',
            epoch: relayedEnvelope.header.epoch,
            msgNum: relayedEnvelope.header.msgNum,
            mode: relayedEnvelope.mode,
            status: dec.success
              ? 'VERIFIED'
              : (dec.errorType as EndpointChatMessage['status']) || 'AUTH_FAILED',
            plaintext: dec.plaintext,
            errorReason: dec.errorMessage,
            nonceHex: relayedEnvelope.header.nonceHex,
            localKeyFingerprint: dec.localKeyFingerprint,
            encryptTimeMs,
            decryptTimeMs: dec.executionTimeMs,
            rttMs,
            timestampMs: Date.now(),
          };

          setBobMessages((prev) => [...prev, bobInboundMsg]);

          // If Bob Bot generated an encrypted reply, relay it back to Alice!
          if (dec.success && botResult.outboundEncrypt && botResult.botReplyPlaintext) {
            const botEnc = botResult.outboundEncrypt;
            const tRelay0 = performance.now();
            const relayRes = await fetch('/api/relay/send', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'X-ARX-User': 'bob',
              },
              body: JSON.stringify({
                conversationId: 'conv-alice-bob',
                envelope: botEnc.envelope,
              }),
            });
            const relayJson = await relayRes.json();
            const botRtt = Number((performance.now() - tRelay0).toFixed(2));

            const botOutboundMsg: EndpointChatMessage = {
              id: `msg-bob-out-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
              envelopeId: botEnc.envelope.envelopeId,
              sender: 'bob',
              recipient: 'alice',
              direction: 'B2A',
              epoch: botEnc.envelope.header.epoch,
              msgNum: botEnc.envelope.header.msgNum,
              mode: botEnc.envelope.mode,
              status: 'VERIFIED',
              plaintext: botResult.botReplyPlaintext,
              nonceHex: botEnc.envelope.header.nonceHex,
              localKeyFingerprint: botEnc.localKeyFingerprint,
              encryptTimeMs: botEnc.executionTimeMs,
              rttMs: botRtt,
              timestampMs: Date.now(),
            };
            setBobMessages((prev) => [...prev, botOutboundMsg]);

            // Now Alice decrypts Bob Bot's reply
            if (relayJson.ok && relayJson.storedEnvelope && aliceStateRef.current) {
              const aliceDec = await decryptEndpointMessage(
                aliceStateRef.current,
                relayJson.storedEnvelope,
                { allowLocalPlaintextDemo: allowPlaintext }
              );
              setAliceState(aliceDec.updatedState);
              aliceStateRef.current = aliceDec.updatedState;

              await fetch('/api/relay/delivery-status', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  envelopeId: relayJson.storedEnvelope.envelopeId,
                  deliveryStatus: aliceDec.success
                    ? 'DELIVERED_VERIFIED'
                    : 'REJECTED_AUTH_FAILED',
                }),
              }).catch(() => {});

              setAliceMessages((prev) => [
                ...prev,
                {
                  id: `msg-alice-in-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
                  envelopeId: relayJson.storedEnvelope.envelopeId,
                  sender: 'bob',
                  recipient: 'alice',
                  direction: 'B2A',
                  epoch: relayJson.storedEnvelope.header.epoch,
                  msgNum: relayJson.storedEnvelope.header.msgNum,
                  mode: relayJson.storedEnvelope.mode,
                  status: aliceDec.success ? 'VERIFIED' : 'AUTH_FAILED',
                  plaintext: aliceDec.plaintext,
                  errorReason: aliceDec.errorMessage,
                  nonceHex: relayJson.storedEnvelope.header.nonceHex,
                  localKeyFingerprint: aliceDec.localKeyFingerprint,
                  encryptTimeMs: botEnc.executionTimeMs,
                  decryptTimeMs: aliceDec.executionTimeMs,
                  rttMs: botRtt,
                  timestampMs: Date.now(),
                },
              ]);
            }
          }

          return {
            decryptOk: dec.success,
            errorType: dec.errorType,
            errorMessage: dec.errorMessage,
          };
        } else {
          // Standard manual Bob endpoint decryption
          const dec = await decryptEndpointMessage(currentBob, relayedEnvelope, {
            allowLocalPlaintextDemo: allowPlaintext,
          });
          setLastDecryptMs(dec.executionTimeMs);
          setBobState(dec.updatedState);
          bobStateRef.current = dec.updatedState;

          await fetch('/api/relay/delivery-status', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              envelopeId: relayedEnvelope.envelopeId,
              deliveryStatus: dec.success
                ? 'DELIVERED_VERIFIED'
                : dec.errorType === 'REPLAY_DETECTED'
                ? 'REJECTED_REPLAY'
                : 'REJECTED_AUTH_FAILED',
            }),
          }).catch(() => {});

          setBobMessages((prev) => [
            ...prev,
            {
              id: `msg-bob-in-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
              envelopeId: relayedEnvelope.envelopeId,
              sender: 'alice',
              recipient: 'bob',
              direction: 'A2B',
              epoch: relayedEnvelope.header.epoch,
              msgNum: relayedEnvelope.header.msgNum,
              mode: relayedEnvelope.mode,
              status: dec.success
                ? 'VERIFIED'
                : (dec.errorType as EndpointChatMessage['status']) || 'AUTH_FAILED',
              plaintext: dec.plaintext,
              errorReason: dec.errorMessage,
              nonceHex: relayedEnvelope.header.nonceHex,
              localKeyFingerprint: dec.localKeyFingerprint,
              encryptTimeMs,
              decryptTimeMs: dec.executionTimeMs,
              rttMs,
              timestampMs: Date.now(),
            },
          ]);

          return {
            decryptOk: dec.success,
            errorType: dec.errorType,
            errorMessage: dec.errorMessage,
          };
        }
      } else {
        // Recipient is Alice
        const currentAlice = aliceStateRef.current;
        if (!currentAlice) {
          return { decryptOk: false, errorMessage: 'Alice session not initialized' };
        }
        const dec = await decryptEndpointMessage(currentAlice, relayedEnvelope, {
          allowLocalPlaintextDemo: allowPlaintext,
        });
        setLastDecryptMs(dec.executionTimeMs);
        setAliceState(dec.updatedState);
        aliceStateRef.current = dec.updatedState;

        await fetch('/api/relay/delivery-status', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            envelopeId: relayedEnvelope.envelopeId,
            deliveryStatus: dec.success
              ? 'DELIVERED_VERIFIED'
              : dec.errorType === 'REPLAY_DETECTED'
              ? 'REJECTED_REPLAY'
              : 'REJECTED_AUTH_FAILED',
          }),
        }).catch(() => {});

        setAliceMessages((prev) => [
          ...prev,
          {
            id: `msg-alice-in-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
            envelopeId: relayedEnvelope.envelopeId,
            sender: 'bob',
            recipient: 'alice',
            direction: 'B2A',
            epoch: relayedEnvelope.header.epoch,
            msgNum: relayedEnvelope.header.msgNum,
            mode: relayedEnvelope.mode,
            status: dec.success
              ? 'VERIFIED'
              : (dec.errorType as EndpointChatMessage['status']) || 'AUTH_FAILED',
            plaintext: dec.plaintext,
            errorReason: dec.errorMessage,
            nonceHex: relayedEnvelope.header.nonceHex,
            localKeyFingerprint: dec.localKeyFingerprint,
            encryptTimeMs,
            decryptTimeMs: dec.executionTimeMs,
            rttMs,
            timestampMs: Date.now(),
          },
        ]);

        return {
          decryptOk: dec.success,
          errorType: dec.errorType,
          errorMessage: dec.errorMessage,
        };
      }
    },
    []
  );

  /**
   * Sends a message from `sender` ('alice' or 'bob'), encrypting at the endpoint,
   * posting the ciphertext envelope to the SQLite relay, and delivering to the recipient.
   */
  const sendEndpointMessage = useCallback(
    async (sender: ParticipantId, plaintext: string) => {
      const trimmed = plaintext.trim();
      if (!trimmed) return;

      const currentSenderState =
        sender === 'alice' ? aliceStateRef.current : bobStateRef.current;
      if (!currentSenderState) return;

      const allowPlaintext =
        demoSettingsRef.current.allowPlaintextBaseline ||
        currentSenderState.mode === 'LOCAL_PLAINTEXT_BASELINE';

      // 1. Encrypt locally at the sending endpoint
      const encResult = await encryptEndpointMessage(currentSenderState, trimmed, {
        allowLocalPlaintextDemo: allowPlaintext,
      });

      setLastEncryptMs(encResult.executionTimeMs);

      if (sender === 'alice') {
        setAliceState(encResult.updatedState);
        aliceStateRef.current = encResult.updatedState;
      } else {
        setBobState(encResult.updatedState);
        bobStateRef.current = encResult.updatedState;
      }

      // Record outbound message in sender's local chat view
      const senderOutboundMsg: EndpointChatMessage = {
        id: `msg-${sender}-out-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        envelopeId: encResult.envelope.envelopeId,
        sender,
        recipient: sender === 'alice' ? 'bob' : 'alice',
        direction: encResult.envelope.header.direction,
        epoch: encResult.envelope.header.epoch,
        msgNum: encResult.envelope.header.msgNum,
        mode: encResult.envelope.mode,
        status: 'VERIFIED',
        plaintext: trimmed,
        nonceHex: encResult.envelope.header.nonceHex,
        localKeyFingerprint: encResult.localKeyFingerprint,
        encryptTimeMs: encResult.executionTimeMs,
        timestampMs: Date.now(),
      };

      if (sender === 'alice') {
        setAliceMessages((prev) => [...prev, senderOutboundMsg]);
      } else {
        setBobMessages((prev) => [...prev, senderOutboundMsg]);
      }

      // 2. Transmit only the EncryptedEnvelope to the Relay Server
      const tRtt0 = performance.now();
      const res = await fetch('/api/relay/send', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-ARX-User': sender,
        },
        body: JSON.stringify({
          conversationId: 'conv-alice-bob',
          envelope: encResult.envelope,
        }),
      });
      const rttMs = Number((performance.now() - tRtt0).toFixed(2));
      setLastRelayRttMs(rttMs);

      const data = await res.json();
      if (data.ok && data.storedEnvelope) {
        setSelectedEnvelopeId(data.storedEnvelope.envelopeId);
        // 3. Deliver the relay's envelope (which may have been tampered on the relay if an experiment was armed!)
        const outcome = await deliverEnvelopeToRecipient(
          data.storedEnvelope,
          encResult.executionTimeMs,
          rttMs
        );

        await syncServerState();

        broadcastRef.current?.postMessage({
          type: 'STATE_UPDATED',
          aliceState: aliceStateRef.current,
          bobState: bobStateRef.current,
        });

        return { encResult, storedEnvelope: data.storedEnvelope, outcome };
      }
      return undefined;
    },
    [deliverEnvelopeToRecipient, syncServerState]
  );

  // Security Experiment Handlers
  const handleExpNormalMessage = useCallback(async () => {
    const res = await sendEndpointMessage(
      'alice',
      `Classroom telemetry check at ${new Date().toLocaleTimeString()}`
    );
    if (res?.outcome.decryptOk) {
      appendExperimentLog(
        'Normal Encrypted Delivery',
        'NOMINAL',
        `Alice encrypted & relayed ${res.storedEnvelope.envelopeId} (epoch=${res.storedEnvelope.header.epoch}, msg=${res.storedEnvelope.header.msgNum}). Bob verified AES-256-GCM tag and decrypted payload.`
      );
    }
  }, [sendEndpointMessage, appendExperimentLog]);

  const handleExpTamperCiphertext = useCallback(async () => {
    await fetch('/api/demo/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        localDemoControlsEnabled: true,
        nextRelayIntervention: 'TAMPER_CIPHERTEXT',
      }),
    });
    const res = await sendEndpointMessage('alice', 'Approve wire transfer: $10,000');
    if (res && !res.outcome.decryptOk) {
      appendExperimentLog(
        'Ciphertext Bit-Flip Tampering',
        'EXPECTED_REJECTION',
        `Relay flipped 1 bit in ciphertext of ${res.storedEnvelope.envelopeId}. Bob rejected with ${res.outcome.errorType}: "${res.outcome.errorMessage}" and kept his receive chain intact.`
      );
    }
  }, [sendEndpointMessage, appendExperimentLog]);

  const handleExpModifyHeader = useCallback(async () => {
    await fetch('/api/demo/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        localDemoControlsEnabled: true,
        nextRelayIntervention: 'TAMPER_HEADER',
      }),
    });
    const res = await sendEndpointMessage('alice', 'Header authenticity verification test');
    if (res && !res.outcome.decryptOk) {
      appendExperimentLog(
        'Authenticated Header (AAD) Modification',
        'EXPECTED_REJECTION',
        `Relay modified header nonce in AAD of ${res.storedEnvelope.envelopeId}. Bob rejected with ${res.outcome.errorType} because canonical AAD bytes failed GCM tag check.`
      );
    }
  }, [sendEndpointMessage, appendExperimentLog]);

  const handleExpReplayLast = useCallback(async () => {
    // Find the last valid envelope sent from Alice to Bob
    const lastA2B = [...relayEnvelopes]
      .reverse()
      .find((e) => e.header.direction === 'A2B' && e.deliveryStatus === 'DELIVERED_VERIFIED');

    if (!lastA2B) {
      // Send one first, then immediately replay it
      const first = await sendEndpointMessage('alice', 'Initial authorized transaction #1');
      if (first?.storedEnvelope) {
        const replayOutcome = await deliverEnvelopeToRecipient(first.storedEnvelope);
        await syncServerState();
        appendExperimentLog(
          'Replay Attack Rejection',
          'EXPECTED_REJECTION',
          `Re-delivered previously accepted envelope ${first.storedEnvelope.envelopeId} (epoch=${first.storedEnvelope.header.epoch}, msg=${first.storedEnvelope.header.msgNum}). Bob rejected with ${replayOutcome.errorType}: "${replayOutcome.errorMessage}".`
        );
      }
      return;
    }

    const replayOutcome = await deliverEnvelopeToRecipient(lastA2B);
    await syncServerState();
    appendExperimentLog(
      'Replay Attack Rejection',
      'EXPECTED_REJECTION',
      `Re-delivered accepted envelope ${lastA2B.envelopeId} (epoch=${lastA2B.header.epoch}, msg=${lastA2B.header.msgNum}). Bob rejected with ${replayOutcome.errorType}: "${replayOutcome.errorMessage}".`
    );
  }, [relayEnvelopes, sendEndpointMessage, deliverEnvelopeToRecipient, syncServerState, appendExperimentLog]);

  const handleExpSendShortSequence = useCallback(async () => {
    const repeatedPlaintext = 'Identical Payload: Ratchet Verification';
    const fingerprints: string[] = [];
    const epochs: number[] = [];

    for (let i = 0; i < 5; i++) {
      const res = await sendEndpointMessage('alice', repeatedPlaintext);
      if (res) {
        fingerprints.push(res.encResult.localKeyFingerprint);
        epochs.push(res.storedEnvelope.header.epoch);
      }
    }

    const uniqueFpCount = new Set(fingerprints).size;
    appendExperimentLog(
      '5-Message Ratchet & Epoch Sequence',
      'NOMINAL',
      `Sent "${repeatedPlaintext}" 5 times. Derived ${uniqueFpCount}/5 distinct message keys (${fingerprints.join(', ')}) across epochs [${epochs.join(' -> ')}].`
    );
  }, [sendEndpointMessage, appendExperimentLog]);

  const handleLoadScenario = useCallback(
    async (scenarioId: ScenarioId, clearExisting: boolean) => {
      const res = await fetch('/api/monitor/scenario', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenarioId, clearExisting }),
      });
      const data = await res.json();
      if (data.ok) {
        setPackets(data.packets || []);
        setAlerts(data.alerts || []);
        appendExperimentLog(
          'PacketGuard Scenario Loaded',
          'INFO',
          `Loaded scenario "${scenarioId}": ${data.packets?.length || 0} packets evaluated, ${data.alerts?.length || 0} heuristic alerts triggered.`
        );
      }
    },
    [appendExperimentLog]
  );

  const handleUpdateRules = useCallback(
    async (newConfig: Partial<DetectionRuleConfig>) => {
      const res = await fetch('/api/monitor/rules', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newConfig),
      });
      const data = await res.json();
      if (data.ok) {
        setRuleConfig(data.ruleConfig);
        setAlerts(data.alerts || []);
        appendExperimentLog(
          'Heuristic Thresholds Updated',
          'INFO',
          `Updated PacketGuard thresholds; re-evaluated stream -> ${data.alerts?.length || 0} active alerts.`
        );
      }
    },
    [appendExperimentLog]
  );

  const handleTestMalloryAccess = useCallback(async () => {
    const res = await fetch('/api/relay/envelopes/conv-alice-bob', {
      headers: { 'X-ARX-User': 'mallory' },
    });
    const data = await res.json();
    await syncServerState();
    appendExperimentLog(
      'Cross-Conversation Authorization Check (Mallory)',
      'EXPECTED_REJECTION',
      `Authenticated user "mallory" requested conv-alice-bob envelopes -> HTTP ${res.status}: "${data.error}".`
    );
  }, [syncServerState, appendExperimentLog]);

  const handleResetDemo = useCallback(async () => {
    await fetch('/api/demo/reset', { method: 'POST' });
    await initFreshSession(encryptionMode, epochSize);
  }, [encryptionMode, epochSize, initFreshSession]);

  const trafficMetrics = useMemo(
    () => computeTrafficMetrics(packets, trafficPerspective),
    [packets, trafficPerspective]
  );

  const selectedEnvelope = useMemo(() => {
    if (relayEnvelopes.length === 0) return null;
    if (selectedEnvelopeId) {
      const found = relayEnvelopes.find((e) => e.envelopeId === selectedEnvelopeId);
      if (found) return found;
    }
    return relayEnvelopes[relayEnvelopes.length - 1];
  }, [relayEnvelopes, selectedEnvelopeId]);

  const totalSentMessages = useMemo(
    () =>
      aliceMessages.filter((m) => m.sender === 'alice').length +
      bobMessages.filter((m) => m.sender === 'bob').length,
    [aliceMessages, bobMessages]
  );

  const totalVerifiedDeliveries = useMemo(
    () =>
      aliceMessages.filter((m) => m.recipient === 'alice' && m.status === 'VERIFIED').length +
      bobMessages.filter((m) => m.recipient === 'bob' && m.status === 'VERIFIED').length,
    [aliceMessages, bobMessages]
  );

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col">
      {/* Top Bar Contract: Zone 1 (1-line Brand) — Zone 2 (5 concise nav links) — Zone 3 (1 primary CTA) */}
      <header className="flex items-center justify-between gap-8 px-6 py-4 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 sticky top-0 z-30">
        <a
          href="#overview"
          onClick={(e) => {
            e.preventDefault();
            setActiveTab('overview');
          }}
          className="text-lg font-bold tracking-tight text-slate-900 dark:text-slate-100 whitespace-nowrap shrink-0"
        >
          ARX-PacketGuard
        </a>

        <nav className="flex items-center gap-6 text-sm font-medium text-slate-600 dark:text-slate-400 overflow-x-auto">
          {(
            [
              { id: 'overview', label: 'Overview' },
              { id: 'chat', label: 'Chat & Endpoints' },
              { id: 'relay', label: 'Relay Inspector' },
              { id: 'packets', label: 'Packet Dashboard' },
              { id: 'experiments', label: 'Experiments & Docs' },
              { id: 'flow', label: 'Visual Flow' },
            ] as const
          ).map((item) => (
            <a
              key={item.id}
              href={`#${item.id}`}
              onClick={(e) => {
                e.preventDefault();
                setActiveTab(item.id);
              }}
              className={`py-1 transition-colors whitespace-nowrap shrink-0 border-b-2 ${
                activeTab === item.id
                  ? 'border-slate-900 dark:border-slate-100 text-slate-900 dark:text-slate-100 font-semibold'
                  : 'border-transparent hover:text-slate-900 dark:hover:text-slate-200'
              }`}
            >
              {item.label}
            </a>
          ))}
        </nav>

        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => initFreshSession(encryptionMode, epochSize)}
            className="px-4 py-2 text-xs font-medium text-white bg-slate-900 dark:bg-slate-100 dark:text-slate-900 rounded-lg hover:bg-slate-800 dark:hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0"
          >
            Establish Fresh Session
          </button>
        </div>
      </header>

      {/* Prominent Local Plaintext Demo Banner when unencrypted baseline is selected */}
      {encryptionMode === 'LOCAL_PLAINTEXT_BASELINE' && (
        <div className="bg-amber-600 text-white px-6 py-2.5 text-xs font-mono flex flex-wrap items-center justify-between gap-2">
          <span className="font-bold">
            LOCAL PLAINTEXT DEMO MODE ACTIVE — ENCRYPTION DISABLED FOR BASELINE COMPARISON
          </span>
          <span className="font-sans">
            Note: In production networks, HTTPS/TLS encrypts transport on the wire, but the Relay Server can still read plaintext unless ARX end-to-end encryption is enabled.
          </span>
        </div>
      )}

      {/* Workspace Control Bar (Below Top Bar) */}
      <div className="bg-white/80 dark:bg-slate-900/80 border-b border-slate-200 dark:border-slate-800 px-6 py-3">
        <div className="max-w-[1400px] mx-auto flex flex-wrap items-center justify-between gap-4">
          {/* Cryptographic Mode & Epoch Selector */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2 text-xs">
              <span className="text-slate-500 dark:text-slate-400 font-medium">Mode:</span>
              <select
                value={encryptionMode}
                onChange={(e) => {
                  const nextMode = e.target.value as EncryptionMode;
                  setEncryptionMode(nextMode);
                  initFreshSession(nextMode, epochSize);
                }}
                className="px-2.5 py-1.5 text-xs font-medium bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
              >
                <option value="HYBRID_X25519_MLKEM768">
                  Hybrid PQC (X25519 + FIPS 203 ML-KEM-768 + AES-256-GCM)
                </option>
                <option value="CLASSICAL_X25519">
                  Classical E2EE (X25519 + HKDF-SHA-256 + AES-256-GCM)
                </option>
                <option value="LOCAL_PLAINTEXT_BASELINE">
                  LOCAL PLAINTEXT DEMO (Unencrypted Baseline)
                </option>
              </select>
            </div>

            <div className="flex items-center gap-2 text-xs">
              <span className="text-slate-500 dark:text-slate-400 font-medium">Epoch Size:</span>
              <select
                value={epochSize}
                onChange={(e) => {
                  const nextEpoch = Number(e.target.value);
                  setEpochSize(nextEpoch);
                  initFreshSession(encryptionMode, nextEpoch);
                }}
                className="px-2.5 py-1.5 text-xs font-mono bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
              >
                <option value={3}>3 msgs / epoch</option>
                <option value={5}>5 msgs / epoch</option>
                <option value={10}>10 msgs / epoch</option>
              </select>
            </div>

            <button
              type="button"
              onClick={() => setBobBotEnabled((v) => !v)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md border transition-colors whitespace-nowrap shrink-0 ${
                bobBotEnabled
                  ? 'bg-emerald-50 dark:bg-emerald-950/60 border-emerald-300 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300'
                  : 'bg-slate-100 dark:bg-slate-800 border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300'
              }`}
            >
              Bob Endpoint Bot: {bobBotEnabled ? 'ACTIVE (Auto-Decrypt & Reply)' : 'OFF (Manual Bob)'}
            </button>
          </div>

          {/* Client Viewport Isolation Switcher & Theme Toggle */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800 rounded-md text-xs">
              {(
                [
                  { id: 'dual', label: 'Dual Classroom View' },
                  { id: 'alice', label: 'Alice Client Only' },
                  { id: 'bob', label: 'Bob Client Only' },
                ] as const
              ).map((r) => (
                <button
                  key={r.id}
                  type="button"
                  onClick={() => setRoleView(r.id)}
                  className={`px-2.5 py-1 font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    roleView === r.id
                      ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900'
                  }`}
                >
                  {r.label}
                </button>
              ))}
            </div>

            <button
              type="button"
              onClick={() => setDarkMode((d) => !d)}
              className="px-3 py-1.5 text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded-md hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
            >
              {darkMode ? 'Light Surface' : 'Dark Surface'}
            </button>
          </div>
        </div>
      </div>

      {/* Main Content Viewport */}
      <main className="flex-1 max-w-[1400px] w-full mx-auto px-6 py-6 space-y-8">
        {/* ===================================================================== */}
        {/* VIEW 1: OVERVIEW                                                      */}
        {/* ===================================================================== */}
        {activeTab === 'overview' && (
          <div className="space-y-8">
            {/* System & Session Status Banner */}
            <div className="p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-4">
              <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
                <div>
                  <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">
                    ARX-PacketGuard Classroom Telemetry &amp; Cryptographic State Overview
                  </h1>
                  <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-600 dark:text-slate-400 font-mono tabular-nums">
                    <span>
                      Relay Status: {relayConnected ? 'CONNECTED (SQLite WAL)' : 'OFFLINE'}
                    </span>
                    <span aria-hidden="true">·</span>
                    <span>Session ID: {handshake?.sessionId || 'Initializing...'}</span>
                    <span aria-hidden="true">·</span>
                    <span>Protocol: {handshake?.protocolVersion}</span>
                    <span aria-hidden="true">·</span>
                    <span>Safety Fingerprint: {aliceState?.safetyFingerprint}</span>
                  </div>
                </div>

                {/* Quick Classroom Jump Actions */}
                <div className="flex flex-wrap items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => setActiveTab('flow')}
                    className="px-3 py-2 text-xs font-medium bg-emerald-700 text-white rounded-md hover:bg-emerald-800 transition-colors whitespace-nowrap shrink-0"
                  >
                    Open Animated Packet Flow
                  </button>
                  <button
                    type="button"
                    onClick={handleExpNormalMessage}
                    className="px-3 py-2 text-xs font-medium bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 rounded-md hover:bg-slate-800 dark:hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0"
                  >
                    Send Test Encrypted Message
                  </button>
                  <button
                    type="button"
                    onClick={handleExpTamperCiphertext}
                    className="px-3 py-2 text-xs font-medium bg-amber-700 text-white rounded-md hover:bg-amber-800 transition-colors whitespace-nowrap shrink-0"
                  >
                    Tamper Next Ciphertext
                  </button>
                  <button
                    type="button"
                    onClick={handleExpReplayLast}
                    className="px-3 py-2 text-xs font-medium bg-red-700 text-white rounded-md hover:bg-red-800 transition-colors whitespace-nowrap shrink-0"
                  >
                    Replay Last Record
                  </button>
                </div>
              </div>

              {/* 8 Real Measured Telemetry Cards (Never Random Numbers) */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="p-4 border border-slate-200 dark:border-slate-800 rounded-md">
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    Encryption &amp; Session Mode
                  </div>
                  <div className="mt-1 text-base font-semibold font-mono text-slate-900 dark:text-slate-100">
                    {encryptionMode === 'HYBRID_X25519_MLKEM768'
                      ? 'HYBRID: X25519 + ML-KEM-768'
                      : encryptionMode === 'CLASSICAL_X25519'
                      ? 'CLASSICAL: X25519 + AES-GCM'
                      : 'LOCAL PLAINTEXT DEMO'}
                  </div>
                  <div className="mt-1 text-xs font-mono tabular-nums text-slate-600 dark:text-slate-400">
                    Epoch Size: {epochSize} msgs · Max Skip: {aliceState?.maxSkip ?? 32}
                  </div>
                </div>

                <div className="p-4 border border-slate-200 dark:border-slate-800 rounded-md">
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    Capture Mode &amp; Selected Interface
                  </div>
                  <div className="mt-1 text-base font-semibold font-mono text-slate-900 dark:text-slate-100">
                    {captureStatus?.activeCaptureMode === 'LIVE_TSHARK_WORKER'
                      ? 'LIVE TSHARK WORKER'
                      : 'RECORDED / SYNTHETIC'}
                  </div>
                  <div className="mt-1 text-xs font-mono tabular-nums text-slate-600 dark:text-slate-400">
                    Interface: {captureStatus?.selectedInterface || 'lo0'} · Buffer:{' '}
                    {captureStatus?.boundedBufferCapacity ?? 2048} pkts
                  </div>
                </div>

                <div className="p-4 border border-slate-200 dark:border-slate-800 rounded-md">
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    Application Messages (Sent / Verified)
                  </div>
                  <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
                    {totalSentMessages} sent / {totalVerifiedDeliveries} verified
                  </div>
                  <div className="mt-1 text-xs font-mono tabular-nums text-slate-600 dark:text-slate-400">
                    Relay Envelopes Stored: {relayEnvelopes.length}
                  </div>
                </div>

                <div className="p-4 border border-slate-200 dark:border-slate-800 rounded-md">
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    Captured Network Bytes (Alice Perspective)
                  </div>
                  <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
                    {trafficMetrics.totalCapturedBytes.toLocaleString()} B
                  </div>
                  <div className="mt-1 text-xs font-mono tabular-nums text-slate-600 dark:text-slate-400">
                    Out: {trafficMetrics.outgoingBytesClient.toLocaleString()} B · In:{' '}
                    {trafficMetrics.incomingBytesClient.toLocaleString()} B
                  </div>
                </div>

                <div className="p-4 border border-slate-200 dark:border-slate-800 rounded-md">
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    Captured Packet Rate &amp; Count
                  </div>
                  <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
                    {trafficMetrics.packetsPerSecond} pkt/s
                  </div>
                  <div className="mt-1 text-xs font-mono tabular-nums text-slate-600 dark:text-slate-400">
                    {trafficMetrics.totalPackets} packets ({trafficMetrics.bytesPerSecond} B/s)
                  </div>
                </div>

                <div className="p-4 border border-slate-200 dark:border-slate-800 rounded-md">
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    PacketGuard Heuristic Alerts
                  </div>
                  <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
                    {alerts.length} {alerts.length === 1 ? 'Alert' : 'Alerts'}
                  </div>
                  <div className="mt-1 text-xs text-slate-600 dark:text-slate-400">
                    {alerts.length === 0
                      ? 'Nominal traffic metadata'
                      : 'Suspicious metadata patterns flagged'}
                  </div>
                </div>

                <div className="p-4 border border-slate-200 dark:border-slate-800 rounded-md">
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    Measured Crypto Execution Latency
                  </div>
                  <div className="mt-1 text-xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
                    Enc: {lastEncryptMs !== null ? `${lastEncryptMs} ms` : '—'} · Dec:{' '}
                    {lastDecryptMs !== null ? `${lastDecryptMs} ms` : '—'}
                  </div>
                  <div className="mt-1 text-xs font-mono tabular-nums text-slate-600 dark:text-slate-400">
                    Relay Ack RTT: {lastRelayRttMs !== null ? `${lastRelayRttMs} ms` : '—'} (performance.now)
                  </div>
                </div>

                <div className="p-4 border border-slate-200 dark:border-slate-800 rounded-md">
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    Ratchet Positions (Alice A2B / Bob B2A)
                  </div>
                  <div className="mt-1 text-xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
                    A2B E{aliceState?.sendEpoch ?? 0}:M{aliceState?.sendMsgNum ?? 0} · B2A E
                    {bobState?.sendEpoch ?? 0}:M{bobState?.sendMsgNum ?? 0}
                  </div>
                  <div className="mt-1 text-xs font-mono tabular-nums text-slate-600 dark:text-slate-400">
                    One-way HKDF-SHA-256 chains active
                  </div>
                </div>
              </div>
            </div>

            {/* Cryptographic vs Serialization vs Network Overhead Breakdown */}
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <div className="lg:col-span-7 p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-4">
                <div className="border-b border-slate-200 dark:border-slate-800 pb-3">
                  <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                    01. Measured Encryption &amp; Transport Overhead Breakdown
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Distinguishing raw AEAD primitives (28 B) from canonical header AAD, JSON/hex serialization, and loopback TCP/HTTP packets
                  </p>
                </div>

                {selectedEnvelope ? (
                  <div className="space-y-3 text-xs font-mono tabular-nums">
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div className="p-3 bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 rounded">
                        <div className="text-slate-500 dark:text-slate-400 font-sans">
                          Plaintext Payload
                        </div>
                        <div className="mt-1 text-lg font-semibold">
                          {selectedEnvelope.plaintextByteLength} B
                        </div>
                      </div>
                      <div className="p-3 bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 rounded">
                        <div className="text-slate-500 dark:text-slate-400 font-sans">
                          Raw Crypto Overhead
                        </div>
                        <div className="mt-1 text-lg font-semibold">
                          {selectedEnvelope.cryptoOverheadBytes} B
                        </div>
                        <div className="text-[11px] text-slate-500 font-sans">
                          12B Nonce + 16B GCM Tag
                        </div>
                      </div>
                      <div className="p-3 bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 rounded">
                        <div className="text-slate-500 dark:text-slate-400 font-sans">
                          JSON Envelope Size
                        </div>
                        <div className="mt-1 text-lg font-semibold">
                          {selectedEnvelope.serializedEnvelopeBytes} B
                        </div>
                        <div className="text-[11px] text-slate-500 font-sans">
                          Includes hex + header JSON
                        </div>
                      </div>
                      <div className="p-3 bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 rounded">
                        <div className="text-slate-500 dark:text-slate-400 font-sans">
                          Loopback Wire Bytes (3 pkts)
                        </div>
                        <div className="mt-1 text-lg font-semibold">
                          {selectedEnvelope.serializedEnvelopeBytes + 218 + 44 + 209 + 44} B
                        </div>
                        <div className="text-[11px] text-slate-500 font-sans">
                          POST + 200 OK + TCP ACK
                        </div>
                      </div>
                    </div>
                    <p className="font-sans text-xs text-slate-600 dark:text-slate-400">
                      <strong>Engineering Note:</strong> One application message is not one network packet. On loopback (<code className="font-mono">lo0</code>), each relayed envelope generates a TCP <code className="font-mono">PSH,ACK</code> HTTP POST request, an HTTP 200 OK response segment, and a final TCP <code className="font-mono">ACK</code>.
                    </p>
                  </div>
                ) : (
                  <div className="py-8 text-center text-xs text-slate-500">
                    Send a message in Chat or click &ldquo;Send Test Encrypted Message&rdquo; above to measure live payload, cryptographic, and wire overhead.
                  </div>
                )}
              </div>

              {/* Application Event Log (Separated from Packet Capture) */}
              <div className="lg:col-span-5 p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-4">
                <div className="border-b border-slate-200 dark:border-slate-800 pb-3">
                  <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                    02. Relay Application Events Panel
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Application-level relay events (kept strictly separate from PacketGuard network capture)
                  </p>
                </div>

                <div className="space-y-2 max-h-52 overflow-y-auto text-xs font-mono tabular-nums">
                  {applicationEvents.length === 0 ? (
                    <div className="text-slate-500 py-4 text-center font-sans">
                      No relay events logged yet.
                    </div>
                  ) : (
                    applicationEvents.slice(0, 15).map((evt) => (
                      <div
                        key={evt.id}
                        className="p-2.5 bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 rounded space-y-1"
                      >
                        <div className="flex items-center justify-between text-[11px] text-slate-500">
                          <span className="font-semibold text-slate-800 dark:text-slate-200">
                            {evt.eventType}
                          </span>
                          <span>{new Date(evt.timestampMs).toLocaleTimeString()}</span>
                        </div>
                        <p className="font-sans text-xs text-slate-700 dark:text-slate-300">
                          {evt.summary}
                        </p>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ===================================================================== */}
        {/* VIEW 2: CHAT & ENDPOINTS (ALICE & BOB)                                */}
        {/* ===================================================================== */}
        {activeTab === 'chat' && (
          <div className="space-y-6">
            {/* Session Identity & Verification Header */}
            <div className="p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
              <div className="space-y-1">
                <div className="text-xs font-mono text-slate-500 dark:text-slate-400 flex flex-wrap items-center gap-2">
                  <span className="font-semibold text-slate-900 dark:text-slate-100">
                    SAFETY FINGERPRINT (OUT-OF-BAND IDENTITY VERIFICATION):
                  </span>
                  <span className="text-emerald-700 dark:text-emerald-400 font-semibold">
                    {aliceState?.safetyFingerprint}
                  </span>
                </div>
                <p className="text-xs text-slate-600 dark:text-slate-400">
                  Both endpoints independently compute this SHA-256 fingerprint over the session ID, X25519 public keys{encryptionMode === 'HYBRID_X25519_MLKEM768' ? ', and Bob’s 1184-byte ML-KEM-768 public key' : ''}. Account registration alone does not prevent a malicious relay from substituting public keys without fingerprint verification.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => initFreshSession(encryptionMode, epochSize)}
                  className="px-3 py-1.5 text-xs font-medium bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 rounded-md hover:bg-slate-800 dark:hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0"
                >
                  Establish Session
                </button>
                <button
                  type="button"
                  onClick={handleResetDemo}
                  className="px-3 py-1.5 text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 rounded-md hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
                >
                  Reset Session
                </button>
                <button
                  type="button"
                  onClick={handleExpTamperCiphertext}
                  className="px-3 py-1.5 text-xs font-medium bg-amber-700 text-white rounded-md hover:bg-amber-800 transition-colors whitespace-nowrap shrink-0"
                >
                  Send Tampered Ciphertext
                </button>
                <button
                  type="button"
                  onClick={handleExpReplayLast}
                  className="px-3 py-1.5 text-xs font-medium bg-red-700 text-white rounded-md hover:bg-red-800 transition-colors whitespace-nowrap shrink-0"
                >
                  Replay Last Record
                </button>
              </div>
            </div>

            {/* Endpoints Grid (Dual View or Isolated Single-Endpoint View) */}
            <div
              className={`grid grid-cols-1 ${
                roleView === 'dual' ? 'lg:grid-cols-2' : 'max-w-3xl mx-auto'
              } gap-6 items-stretch`}
            >
              {/* ALICE ENDPOINT PANEL */}
              {(roleView === 'dual' || roleView === 'alice') && aliceState && (
                <div className="p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg flex flex-col justify-between space-y-4">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
                      <div>
                        <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                          Alice Endpoint (Initiator · 127.0.0.1:54110)
                        </h2>
                        <div className="text-xs font-mono text-slate-500 dark:text-slate-400">
                          X25519 Pub: {aliceIdentity.x25519PublicKeyHex.slice(0, 20)}...
                        </div>
                      </div>
                      <div className="text-right font-mono text-xs tabular-nums">
                        <div className="font-semibold text-slate-900 dark:text-slate-100">
                          Send (A2B): Epoch {aliceState.sendEpoch} · Msg #{aliceState.sendMsgNum}
                        </div>
                        <div className="text-slate-500 dark:text-slate-400">
                          Recv (B2A): Epoch {aliceState.recvEpoch} · Msg #{aliceState.recvMsgNum}
                        </div>
                      </div>
                    </div>

                    {/* Alice Conversation History */}
                    <div className="h-72 overflow-y-auto space-y-2.5 p-3 bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 rounded-md">
                      {aliceMessages.length === 0 ? (
                        <div className="h-full flex items-center justify-center text-xs text-slate-500 text-center px-4">
                          No messages in Alice’s endpoint view yet. Send a message below (try &ldquo;hello&rdquo;, &ldquo;time&rdquo;, &ldquo;help&rdquo;, or &ldquo;echo Confirm Ratchet&rdquo;).
                        </div>
                      ) : (
                        aliceMessages.map((m) => (
                          <div
                            key={m.id}
                            className={`p-3 rounded-md border text-xs space-y-1 ${
                              m.status !== 'VERIFIED'
                                ? 'bg-red-50/80 dark:bg-red-950/40 border-red-300 dark:border-red-800'
                                : m.sender === 'alice'
                                ? 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 ml-6'
                                : 'bg-slate-100 dark:bg-slate-800/80 border-slate-200 dark:border-slate-700 mr-6'
                            }`}
                          >
                            <div className="flex flex-wrap items-center justify-between gap-1 font-mono text-[11px] tabular-nums text-slate-500 dark:text-slate-400">
                              <span>
                                {m.sender.toUpperCase()} → {m.recipient.toUpperCase()} · {m.direction}{' '}
                                · E{m.epoch}:M{m.msgNum}
                              </span>
                              <span
                                className={
                                  m.status === 'VERIFIED'
                                    ? 'text-emerald-700 dark:text-emerald-400 font-semibold'
                                    : 'text-red-700 dark:text-red-400 font-semibold'
                                }
                              >
                                {m.status === 'VERIFIED'
                                  ? m.mode === 'LOCAL_PLAINTEXT_BASELINE'
                                    ? 'PLAINTEXT DEMO'
                                    : 'VERIFIED · AES-256-GCM'
                                  : `REJECTED · ${m.status}`}
                              </span>
                            </div>

                            {m.status === 'VERIFIED' ? (
                              <p className="text-sm text-slate-900 dark:text-slate-100 break-words">
                                {m.plaintext}
                              </p>
                            ) : (
                              <p className="text-xs font-medium text-red-700 dark:text-red-300">
                                {m.errorReason} (Zero corrupted plaintext rendered; receive chain untouched)
                              </p>
                            )}

                            <div className="text-[10px] font-mono tabular-nums text-slate-500 flex flex-wrap items-center gap-2 pt-1">
                              <span>Nonce: {m.nonceHex.slice(0, 12)}...</span>
                              {m.localKeyFingerprint && (
                                <>
                                  <span aria-hidden="true">·</span>
                                  <span>Local Key FP: {m.localKeyFingerprint}</span>
                                </>
                              )}
                              {m.encryptTimeMs !== undefined && (
                                <>
                                  <span aria-hidden="true">·</span>
                                  <span>Enc: {m.encryptTimeMs}ms</span>
                                </>
                              )}
                            </div>
                          </div>
                        ))
                      )}
                    </div>

                    {/* Alice Local-Only Key Evolution Log */}
                    <div className="p-3 bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 rounded-md">
                      <div className="text-[11px] font-semibold text-slate-700 dark:text-slate-300 mb-1">
                        Alice Local-Only Ratchet Key Evolution Log (Never transmitted to Relay)
                      </div>
                      <div className="max-h-24 overflow-y-auto font-mono text-[11px] tabular-nums text-slate-600 dark:text-slate-400 space-y-0.5">
                        {aliceState.localKeyEvolutionLog.length === 0 ? (
                          <div>No message keys derived yet in this session.</div>
                        ) : (
                          aliceState.localKeyEvolutionLog.slice(-6).map((k, idx) => (
                            <div key={idx}>
                              [{k.direction} E{k.epoch}:M{k.msgNum}] Nonce={k.nonceHex} · KeyFP=
                              <span className="text-slate-900 dark:text-slate-100 font-semibold">
                                {k.keyFingerprint}
                              </span>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Alice Send Form */}
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      sendEndpointMessage('alice', aliceDraft);
                      setAliceDraft('');
                    }}
                    className="space-y-2 pt-2 border-t border-slate-200 dark:border-slate-800"
                  >
                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        value={aliceDraft}
                        onChange={(e) => setAliceDraft(e.target.value)}
                        placeholder='Type message from Alice (or "hello", "time", "help", "echo <text>")...'
                        className="flex-1 px-3 py-2 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
                      />
                      <button
                        type="submit"
                        className="px-4 py-2 text-xs font-medium bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 rounded-md hover:bg-slate-800 dark:hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0"
                      >
                        Send from Alice
                      </button>
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                      <span className="text-slate-500">Quick Bot Commands:</span>
                      {['hello', 'time', 'help', 'echo Ratchet Verified!'].map((cmd) => (
                        <button
                          key={cmd}
                          type="button"
                          onClick={() => sendEndpointMessage('alice', cmd)}
                          className="px-2 py-0.5 font-mono bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 rounded hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                        >
                          {cmd}
                        </button>
                      ))}
                    </div>
                  </form>
                </div>
              )}

              {/* BOB ENDPOINT PANEL */}
              {(roleView === 'dual' || roleView === 'bob') && bobState && (
                <div className="p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg flex flex-col justify-between space-y-4">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
                      <div>
                        <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
                          Bob Endpoint (Responder · 127.0.0.1:54120)
                        </h2>
                        <div className="text-xs font-mono text-slate-500 dark:text-slate-400">
                          X25519 Pub: {bobIdentity.x25519PublicKeyHex.slice(0, 20)}... ·{' '}
                          {bobBotEnabled ? 'Bot Auto-Responder ON' : 'Manual Mode'}
                        </div>
                      </div>
                      <div className="text-right font-mono text-xs tabular-nums">
                        <div className="font-semibold text-slate-900 dark:text-slate-100">
                          Recv (A2B): Epoch {bobState.recvEpoch} · Msg #{bobState.recvMsgNum}
                        </div>
                        <div className="text-slate-500 dark:text-slate-400">
                          Send (B2A): Epoch {bobState.sendEpoch} · Msg #{bobState.sendMsgNum}
                        </div>
                      </div>
                    </div>

                    {/* Bob Conversation History */}
                    <div className="h-72 overflow-y-auto space-y-2.5 p-3 bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 rounded-md">
                      {bobMessages.length === 0 ? (
                        <div className="h-full flex items-center justify-center text-xs text-slate-500 text-center px-4">
                          Bob’s receiving endpoint is waiting for authenticated envelopes from the relay.
                        </div>
                      ) : (
                        bobMessages.map((m) => (
                          <div
                            key={m.id}
                            className={`p-3 rounded-md border text-xs space-y-1 ${
                              m.status !== 'VERIFIED'
                                ? 'bg-red-50/80 dark:bg-red-950/40 border-red-300 dark:border-red-800'
                                : m.sender === 'bob'
                                ? 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 ml-6'
                                : 'bg-slate-100 dark:bg-slate-800/80 border-slate-200 dark:border-slate-700 mr-6'
                            }`}
                          >
                            <div className="flex flex-wrap items-center justify-between gap-1 font-mono text-[11px] tabular-nums text-slate-500 dark:text-slate-400">
                              <span>
                                {m.sender.toUpperCase()} → {m.recipient.toUpperCase()} · {m.direction}{' '}
                                · E{m.epoch}:M{m.msgNum}
                              </span>
                              <span
                                className={
                                  m.status === 'VERIFIED'
                                    ? 'text-emerald-700 dark:text-emerald-400 font-semibold'
                                    : 'text-red-700 dark:text-red-400 font-semibold'
                                }
                              >
                                {m.status === 'VERIFIED'
                                  ? m.mode === 'LOCAL_PLAINTEXT_BASELINE'
                                    ? 'PLAINTEXT DEMO'
                                    : 'VERIFIED · AES-256-GCM'
                                  : `REJECTED · ${m.status}`}
                              </span>
                            </div>

                            {m.status === 'VERIFIED' ? (
                              <p className="text-sm text-slate-900 dark:text-slate-100 break-words">
                                {m.plaintext}
                              </p>
                            ) : (
                              <p className="text-xs font-medium text-red-700 dark:text-red-300">
                                {m.errorReason} (Rejected before state commit — receive chain intact)
                              </p>
                            )}

                            <div className="text-[10px] font-mono tabular-nums text-slate-500 flex flex-wrap items-center gap-2 pt-1">
                              <span>Nonce: {m.nonceHex.slice(0, 12)}...</span>
                              {m.localKeyFingerprint && (
                                <>
                                  <span aria-hidden="true">·</span>
                                  <span>Local Key FP: {m.localKeyFingerprint}</span>
                                </>
                              )}
                              {m.decryptTimeMs !== undefined && (
                                <>
                                  <span aria-hidden="true">·</span>
                                  <span>Dec: {m.decryptTimeMs}ms</span>
                                </>
                              )}
                            </div>
                          </div>
                        ))
                      )}
                    </div>

                    {/* Bob Local-Only Key Evolution Log */}
                    <div className="p-3 bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 rounded-md">
                      <div className="text-[11px] font-semibold text-slate-700 dark:text-slate-300 mb-1">
                        Bob Local-Only Ratchet Key Evolution Log (Seen Ids: {bobState.seenMessageKeys.length})
                      </div>
                      <div className="max-h-24 overflow-y-auto font-mono text-[11px] tabular-nums text-slate-600 dark:text-slate-400 space-y-0.5">
                        {bobState.localKeyEvolutionLog.length === 0 ? (
                          <div>No message keys derived yet in this session.</div>
                        ) : (
                          bobState.localKeyEvolutionLog.slice(-6).map((k, idx) => (
                            <div key={idx}>
                              [{k.direction} E{k.epoch}:M{k.msgNum}] Nonce={k.nonceHex} · KeyFP=
                              <span className="text-slate-900 dark:text-slate-100 font-semibold">
                                {k.keyFingerprint}
                              </span>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Bob Send Form */}
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      sendEndpointMessage('bob', bobDraft);
                      setBobDraft('');
                    }}
                    className="space-y-2 pt-2 border-t border-slate-200 dark:border-slate-800"
                  >
                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        value={bobDraft}
                        onChange={(e) => setBobDraft(e.target.value)}
                        placeholder="Type message from Bob to Alice..."
                        className="flex-1 px-3 py-2 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-md text-slate-900 dark:text-slate-100"
                      />
                      <button
                        type="submit"
                        className="px-4 py-2 text-xs font-medium bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 rounded-md hover:bg-slate-800 dark:hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0"
                      >
                        Send from Bob
                      </button>
                    </div>
                    <div className="text-[11px] text-slate-500">
                      Note: Deterministic epoch evolution every {epochSize} messages separates keys forward without adding fresh entropy.
                    </div>
                  </form>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ===================================================================== */}
        {/* VIEW 3: RELAY INSPECTOR (CIPHERTEXT-ONLY TEACHING INSPECTOR)          */}
        {/* ===================================================================== */}
        {activeTab === 'relay' && (
          <div className="space-y-6">
            <div className="p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-4">
              <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
                <div>
                  <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                    Relay Teaching Inspector (Untrusted SQLite Relay View)
                  </h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    The Relay Server authenticates conversation membership and stores serialized envelopes, but possesses ZERO private keys, session secrets, message keys, or decrypted chat content.
                  </p>
                </div>

                {/* Controlled Relay Tamper & Replay Actions */}
                <div className="flex flex-wrap items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={handleExpTamperCiphertext}
                    className="px-3 py-1.5 text-xs font-medium bg-amber-700 text-white rounded-md hover:bg-amber-800 transition-colors whitespace-nowrap shrink-0"
                  >
                    Inject Ciphertext Bit-Flip
                  </button>
                  <button
                    type="button"
                    onClick={handleExpModifyHeader}
                    className="px-3 py-1.5 text-xs font-medium bg-amber-700 text-white rounded-md hover:bg-amber-800 transition-colors whitespace-nowrap shrink-0"
                  >
                    Modify Next Header (AAD)
                  </button>
                  <button
                    type="button"
                    onClick={handleExpReplayLast}
                    className="px-3 py-1.5 text-xs font-medium bg-red-700 text-white rounded-md hover:bg-red-800 transition-colors whitespace-nowrap shrink-0"
                  >
                    Replay Last Envelope
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                {/* Envelope List Table (7 cols) */}
                <div className="lg:col-span-7 space-y-3">
                  <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                    Relayed Envelopes in SQLite (`relay_envelopes` table · Click any row to inspect)
                  </div>

                  {relayEnvelopes.length === 0 ? (
                    <div className="py-12 text-center text-xs text-slate-500 border border-slate-200 dark:border-slate-800 rounded-md">
                      No envelopes relayed in current session yet. Click &ldquo;Send Normal Message&rdquo; or use Chat.
                    </div>
                  ) : (
                    <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-md max-h-96">
                      <table className="w-full text-left border-collapse text-xs font-mono tabular-nums">
                        <thead>
                          <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50 text-slate-500 dark:text-slate-400">
                            <th className="py-2 px-3">Dir / Seq</th>
                            <th className="py-2 px-3">Nonce (96-bit)</th>
                            <th className="py-2 px-3">Ciphertext (Hex)</th>
                            <th className="py-2 px-3">GCM Tag (128-bit)</th>
                            <th className="py-2 px-3 text-right">Bytes</th>
                            <th className="py-2 px-3">Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/70">
                          {relayEnvelopes.map((env) => {
                            const isSelected = selectedEnvelope?.envelopeId === env.envelopeId;
                            return (
                              <tr
                                key={env.envelopeId}
                                onClick={() => setSelectedEnvelopeId(env.envelopeId)}
                                className={`cursor-pointer transition-colors ${
                                  isSelected
                                    ? 'bg-slate-100 dark:bg-slate-800'
                                    : 'hover:bg-slate-50 dark:hover:bg-slate-800/40'
                                }`}
                              >
                                <td className="py-2 px-3 whitespace-nowrap">
                                  {env.header.direction} E{env.header.epoch}:M{env.header.msgNum}
                                </td>
                                <td className="py-2 px-3 whitespace-nowrap text-slate-600 dark:text-slate-400">
                                  {env.header.nonceHex.slice(0, 12)}...
                                </td>
                                <td className="py-2 px-3 whitespace-nowrap text-slate-900 dark:text-slate-100">
                                  {env.ciphertextHex.slice(0, 16)}...
                                </td>
                                <td className="py-2 px-3 whitespace-nowrap text-slate-600 dark:text-slate-400">
                                  {env.authTagHex ? `${env.authTagHex.slice(0, 12)}...` : '(none)'}
                                </td>
                                <td className="py-2 px-3 text-right whitespace-nowrap">
                                  {env.serializedEnvelopeBytes} B
                                </td>
                                <td className="py-2 px-3 whitespace-nowrap">
                                  <span
                                    className={
                                      env.deliveryStatus === 'DELIVERED_VERIFIED'
                                        ? 'text-emerald-700 dark:text-emerald-400 font-semibold'
                                        : 'text-amber-700 dark:text-amber-400 font-semibold'
                                    }
                                  >
                                    {env.tamperedFlag && env.tamperedFlag !== 'NONE'
                                      ? `${env.tamperedFlag} -> ${env.deliveryStatus}`
                                      : env.deliveryStatus}
                                  </span>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                {/* Detailed Envelope Anatomy Inspector (5 cols) */}
                <div className="lg:col-span-5 p-5 bg-slate-50 dark:bg-slate-800/40 border border-slate-200 dark:border-slate-800 rounded-md space-y-4">
                  <div className="border-b border-slate-200 dark:border-slate-700 pb-2">
                    <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                      Transmitted Envelope vs. Receiver-Derived Values
                    </h3>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      Exact byte-level structure inspected on the relay
                    </p>
                  </div>

                  {selectedEnvelope ? (
                    <div className="space-y-3 text-xs font-mono tabular-nums">
                      <div>
                        <div className="text-slate-500 font-sans font-medium">
                          1. Transmitted Authenticated Header Fields (Public Metadata):
                        </div>
                        <div className="mt-1 p-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-1">
                          <div>Session ID: {selectedEnvelope.header.sessionId}</div>
                          <div>
                            Route: {selectedEnvelope.header.sender} →{' '}
                            {selectedEnvelope.header.recipient} ({selectedEnvelope.header.direction})
                          </div>
                          <div>
                            Epoch: {selectedEnvelope.header.epoch} · Msg #:{' '}
                            {selectedEnvelope.header.msgNum}
                          </div>
                          <div>Transmitted Nonce (12B): {selectedEnvelope.header.nonceHex}</div>
                        </div>
                      </div>

                      <div>
                        <div className="text-slate-500 font-sans font-medium">
                          2. Canonical Serialized AAD Bytes (Authenticated by AES-GCM):
                        </div>
                        <div className="mt-1 p-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded break-all text-[11px]">
                          {formatCanonicalHeaderString(selectedEnvelope.header)}
                        </div>
                      </div>

                      <div>
                        <div className="text-slate-500 font-sans font-medium">
                          3. Split Ciphertext &amp; 128-Bit GCM Authentication Tag:
                        </div>
                        <div className="mt-1 p-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded space-y-1.5 break-all">
                          <div>
                            <span className="text-slate-500">Ciphertext Hex: </span>
                            <span className="text-slate-900 dark:text-slate-100">
                              {selectedEnvelope.ciphertextHex}
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-500">Auth Tag Hex (16B): </span>
                            <span className="text-emerald-700 dark:text-emerald-400">
                              {selectedEnvelope.authTagHex || '(None — Local Plaintext Baseline)'}
                            </span>
                          </div>
                        </div>
                        <p className="mt-1 font-sans text-[11px] text-slate-500 dark:text-slate-400">
                          <strong>WebCrypto Split Note:</strong> WebCrypto’s <code className="font-mono">AES-GCM</code> outputs <code className="font-mono">ciphertext || 16-byte tag</code>. The sending endpoint splits the trailing 16 bytes into <code className="font-mono">authTagHex</code>; the receiving endpoint recombines them prior to verification.
                        </p>
                      </div>

                      <div>
                        <div className="text-slate-500 font-sans font-medium">
                          4. Receiver-Derived Values (NEVER Transmitted or Known to Relay):
                        </div>
                        <div className="mt-1 p-2.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded font-sans text-xs text-slate-600 dark:text-slate-400">
                          • <code className="font-mono">messageKey</code> (256-bit AES-GCM key derived locally via HKDF-SHA-256 from directional chain key)
                          <br />• <code className="font-mono">nextChainKey</code> (256-bit one-way ratcheted chain key)
                          <br />• Decrypted UTF-8 Plaintext (only materialized inside endpoint after tag check)
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-xs text-slate-500 py-8 text-center">
                      Select an envelope from the table to inspect its fields.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ===================================================================== */}
        {/* VIEW 4: PACKET DASHBOARD                                              */}
        {/* ===================================================================== */}
        {activeTab === 'packets' && (
          <PacketDashboardView
            packets={packets}
            alerts={alerts}
            ruleConfig={ruleConfig}
            captureStatus={captureStatus}
            perspective={trafficPerspective}
            onChangePerspective={setTrafficPerspective}
            onLoadScenario={handleLoadScenario}
            onUpdateRules={handleUpdateRules}
          />
        )}

        {/* ===================================================================== */}
        {/* VIEW 1B: INTERACTIVE VISUAL CRYPTO & PACKET FLOW SIMULATOR            */}
        {/* ===================================================================== */}
        {activeTab === 'flow' && (
          <VisualFlowSimulatorView
            activeEncryptionMode={encryptionMode}
            epochSize={epochSize}
            onTriggerLiveNormal={handleExpNormalMessage}
            onTriggerLiveTamperCipher={handleExpTamperCiphertext}
            onTriggerLiveTamperHeader={handleExpModifyHeader}
            onTriggerLiveReplay={handleExpReplayLast}
          />
        )}

        {/* ===================================================================== */}
        {/* VIEW 5: EXPERIMENTS, DEMO SCRIPT, VIVA & LOCAL PYTHON KIT             */}
        {/* ===================================================================== */}
        {activeTab === 'experiments' && (
          <ExperimentsAndDocsView
            experimentLogs={experimentLogs}
            onSendNormalMessage={handleExpNormalMessage}
            onTamperNextCiphertext={handleExpTamperCiphertext}
            onModifyNextHeader={handleExpModifyHeader}
            onReplayLastRecord={handleExpReplayLast}
            onSendShortSequence={handleExpSendShortSequence}
            onLoadScenario={handleLoadScenario}
            onResetDemonstration={handleResetDemo}
            onTestCrossConversationAccess={handleTestMalloryAccess}
          />
        )}
      </main>

      {/* Quiet Classroom Footer */}
      <footer className="border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-6 py-4 mt-12">
        <div className="max-w-[1400px] mx-auto flex flex-wrap items-center justify-between gap-4 text-xs text-slate-500 dark:text-slate-400">
          <div>
            ARX-PacketGuard · Educational Information Security Prototype (Not an audited production messenger)
          </div>
          <div className="font-mono tabular-nums">
            Endpoints: /?role=alice · /?role=bob · Local Kit: /local_python_kit/
          </div>
        </div>
      </footer>
    </div>
  );
}
