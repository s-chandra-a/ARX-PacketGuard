import Database from 'better-sqlite3';
import { execFileSync } from 'child_process';
import { pbkdf2 } from '@noble/hashes/pbkdf2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js';
import {
  tamperAuthenticatedHeader,
  tamperAuthTag,
  tamperCiphertextBitFlip,
  type EncryptedEnvelope,
  type SessionInitHandshake,
} from '../crypto/arxCrypto.ts';
import {
  buildClassroomScenarioPackets,
  DEFAULT_RULE_CONFIG,
  evaluatePacketGuardRules,
  generateLoopbackPacketsForEnvelope,
  type DetectionRuleConfig,
  type HeuristicAlert,
  type PacketMetadataRecord,
  type ScenarioId,
} from '../monitor/packetGuardEngine.ts';

export type RelayInterventionMode =
  | 'NONE'
  | 'TAMPER_CIPHERTEXT'
  | 'TAMPER_HEADER'
  | 'TAMPER_TAG';

export interface LocalDemoSettings {
  localDemoControlsEnabled: boolean;
  allowPlaintextBaseline: boolean;
  nextRelayIntervention: RelayInterventionMode;
}

export interface LiveCaptureStatus {
  tsharkInstalled: boolean;
  tsharkVersion: string | null;
  capturePermissionGranted: boolean;
  activeCaptureMode: 'RECORDED_OR_SYNTHETIC' | 'LIVE_TSHARK_WORKER';
  selectedInterface: string;
  availableInterfaces: string[];
  fallbackReason: string;
  boundedBufferCapacity: number;
  droppedPacketsCount: number;
}

export interface RelayEventLogEntry {
  id: string;
  timestampMs: number;
  eventType: 'SESSION_INIT' | 'ENVELOPE_RELAYED' | 'RELAY_TAMPER_APPLIED' | 'RELAY_REPLAY_INJECTED' | 'ACCESS_DENIED';
  summary: string;
}

function hashPassword(password: string, saltHex: string): string {
  const derived = pbkdf2(sha256, utf8ToBytes(password), utf8ToBytes(saltHex), {
    c: 10000,
    dkLen: 32,
  });
  return bytesToHex(derived);
}

export class ArxRelayStore {
  private db: Database.Database;
  private demoSettings: LocalDemoSettings = {
    localDemoControlsEnabled: true,
    allowPlaintextBaseline: false,
    nextRelayIntervention: 'NONE',
  };
  private ruleConfig: DetectionRuleConfig = { ...DEFAULT_RULE_CONFIG };
  private sessionTokens = new Map<string, string>(); // token -> username
  private applicationEventLog: RelayEventLogEntry[] = [];

  constructor(dbPath = ':memory:') {
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.initializeSchema();
    this.seedDefaults();
  }

  private initializeSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS accounts (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        display_name TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS conversations (
        conversation_id TEXT PRIMARY KEY,
        participant_a TEXT NOT NULL,
        participant_b TEXT NOT NULL,
        handshake_json TEXT,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS relay_envelopes (
        seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
        envelope_id TEXT UNIQUE NOT NULL,
        conversation_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        protocol_version TEXT NOT NULL,
        sender TEXT NOT NULL,
        recipient TEXT NOT NULL,
        direction TEXT NOT NULL,
        epoch INTEGER NOT NULL,
        msg_num INTEGER NOT NULL,
        nonce_hex TEXT NOT NULL,
        ciphertext_hex TEXT NOT NULL,
        auth_tag_hex TEXT NOT NULL,
        mode TEXT NOT NULL,
        plaintext_byte_length INTEGER NOT NULL,
        serialized_envelope_bytes INTEGER NOT NULL,
        crypto_overhead_bytes INTEGER NOT NULL,
        tampered_flag TEXT NOT NULL,
        delivery_status TEXT NOT NULL,
        timestamp_ms INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS packet_metadata (
        seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
        packet_id TEXT UNIQUE NOT NULL,
        timestamp_ms INTEGER NOT NULL,
        source_type TEXT NOT NULL,
        scenario_name TEXT NOT NULL,
        interface_name TEXT NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        src_port INTEGER,
        dst_port INTEGER,
        protocol TEXT NOT NULL,
        captured_bytes INTEGER NOT NULL,
        tcp_flags TEXT,
        arp_sender_mac TEXT,
        arp_sender_ip TEXT,
        arp_operation TEXT,
        dns_query_name TEXT,
        dns_query_type TEXT,
        linked_envelope_id TEXT,
        notes TEXT
      );

      CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY,
        rule_id TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        timestamp_ms INTEGER NOT NULL,
        source_type TEXT NOT NULL,
        scenario_name TEXT NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        observed_value TEXT NOT NULL,
        threshold_value TEXT NOT NULL,
        evidence_summary TEXT NOT NULL,
        benign_explanation TEXT NOT NULL,
        sample_packet_ids_json TEXT NOT NULL
      );
    `);
  }

  private seedDefaults(): void {
    const insertAccount = this.db.prepare(`
      INSERT OR IGNORE INTO accounts (username, password_hash, salt, display_name, created_at)
      VALUES (?, ?, ?, ?, ?)
    `);

    const now = Date.now();
    const demoUsers = [
      { username: 'alice', pass: 'alice-demo-pass', name: 'Alice (Endpoint A)' },
      { username: 'bob', pass: 'bob-demo-pass', name: 'Bob (Endpoint B)' },
      { username: 'mallory', pass: 'mallory-demo-pass', name: 'Mallory (Unauthorized 3rd Party)' },
    ];

    for (const u of demoUsers) {
      const salt = `salt-${u.username}-arx-v1`;
      const hash = hashPassword(u.pass, salt);
      insertAccount.run(u.username, hash, salt, u.name, now);
      // Pre-register classroom tokens for deterministic local/API testing
      this.sessionTokens.set(`demo-token-${u.username}`, u.username);
    }

    const insertConv = this.db.prepare(`
      INSERT OR IGNORE INTO conversations (conversation_id, participant_a, participant_b, handshake_json, updated_at)
      VALUES (?, ?, ?, ?, ?)
    `);
    insertConv.run('conv-alice-bob', 'alice', 'bob', null, now);

    // Seed initial benign recorded packet trace if packet_metadata is empty
    const countRow = this.db.prepare('SELECT COUNT(*) as cnt FROM packet_metadata').get() as {
      cnt: number;
    };
    if (countRow.cnt === 0) {
      this.loadScenarioPackets('BENIGN_BASELINE_ALL');
    }
  }

  public authenticateUser(username: string, password: string): { ok: boolean; token?: string; error?: string } {
    const row = this.db
      .prepare('SELECT username, password_hash, salt FROM accounts WHERE username = ?')
      .get(username) as { username: string; password_hash: string; salt: string } | undefined;

    if (!row) {
      return { ok: false, error: 'Invalid credentials' };
    }
    const candidateHash = hashPassword(password, row.salt);
    if (candidateHash !== row.password_hash) {
      return { ok: false, error: 'Invalid credentials' };
    }
    const token = `tok-${username}-${Date.now()}`;
    this.sessionTokens.set(token, username);
    return { ok: true, token };
  }

  public resolveUserFromHeader(userOrToken?: string): string | null {
    if (!userOrToken) return null;
    if (this.sessionTokens.has(userOrToken)) {
      return this.sessionTokens.get(userOrToken)!;
    }
    if (['alice', 'bob', 'mallory'].includes(userOrToken.toLowerCase())) {
      return userOrToken.toLowerCase();
    }
    return null;
  }

  /**
   * Enforces conversation membership authorization on every relevant endpoint.
   */
  public verifyConversationMembership(conversationId: string, username: string | null): boolean {
    if (!username) return false;
    const row = this.db
      .prepare('SELECT participant_a, participant_b FROM conversations WHERE conversation_id = ?')
      .get(conversationId) as { participant_a: string; participant_b: string } | undefined;

    if (!row) return false;
    const allowed = row.participant_a === username || row.participant_b === username;
    if (!allowed) {
      this.logAppEvent(
        'ACCESS_DENIED',
        `User "${username}" denied access to conversation "${conversationId}" (members: ${row.participant_a}, ${row.participant_b}).`
      );
    }
    return allowed;
  }

  private logAppEvent(eventType: RelayEventLogEntry['eventType'], summary: string): void {
    this.applicationEventLog.unshift({
      id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      timestampMs: Date.now(),
      eventType,
      summary,
    });
    if (this.applicationEventLog.length > 100) {
      this.applicationEventLog.length = 100;
    }
  }

  public getApplicationEvents(): RelayEventLogEntry[] {
    return this.applicationEventLog;
  }

  public getDemoSettings(): LocalDemoSettings {
    return { ...this.demoSettings };
  }

  public updateDemoSettings(partial: Partial<LocalDemoSettings>): LocalDemoSettings {
    this.demoSettings = {
      ...this.demoSettings,
      ...partial,
    };
    return this.getDemoSettings();
  }

  public getRuleConfig(): DetectionRuleConfig {
    return { ...this.ruleConfig };
  }

  public updateRuleConfig(partial: Partial<DetectionRuleConfig>): {
    ruleConfig: DetectionRuleConfig;
    alerts: HeuristicAlert[];
  } {
    this.ruleConfig = {
      ...this.ruleConfig,
      ...partial,
    };
    const alerts = this.recomputeAlerts();
    return { ruleConfig: this.getRuleConfig(), alerts };
  }

  public storeHandshake(
    conversationId: string,
    actingUser: string | null,
    handshake: SessionInitHandshake
  ): { ok: boolean; status: number; error?: string } {
    if (!this.verifyConversationMembership(conversationId, actingUser)) {
      return { ok: false, status: 403, error: 'Cross-conversation access denied: Not a conversation member.' };
    }
    this.db
      .prepare('UPDATE conversations SET handshake_json = ?, updated_at = ? WHERE conversation_id = ?')
      .run(JSON.stringify(handshake), Date.now(), conversationId);

    // Clear old session envelopes on fresh session establishment
    this.db.prepare('DELETE FROM relay_envelopes WHERE conversation_id = ?').run(conversationId);

    this.logAppEvent(
      'SESSION_INIT',
      `Session ${handshake.sessionId} established (${handshake.mode}, epochSize=${handshake.epochSize}). Relay stores public handshake parameters only.`
    );
    return { ok: true, status: 200 };
  }

  /**
   * Receives an encrypted envelope from a participant, optionally applies armed classroom
   * tamper intervention, persists only the envelope (never plaintext or secret keys),
   * and records loopback packet metadata.
   */
  public relayEnvelope(
    conversationId: string,
    actingUser: string | null,
    incomingEnvelope: EncryptedEnvelope
  ): {
    ok: boolean;
    status: number;
    error?: string;
    storedEnvelope?: EncryptedEnvelope & { deliveryStatus: string };
  } {
    if (!this.verifyConversationMembership(conversationId, actingUser)) {
      return {
        ok: false,
        status: 403,
        error: 'Cross-conversation access denied: User is not authorized for this conversation.',
      };
    }

    if (
      incomingEnvelope.mode === 'LOCAL_PLAINTEXT_BASELINE' &&
      (!this.demoSettings.localDemoControlsEnabled || !this.demoSettings.allowPlaintextBaseline)
    ) {
      return {
        ok: false,
        status: 400,
        error: 'Local Plaintext Baseline mode is disabled in relay settings.',
      };
    }

    let finalEnvelope: EncryptedEnvelope = {
      ...incomingEnvelope,
      header: { ...incomingEnvelope.header },
      tamperedFlag: incomingEnvelope.tamperedFlag || 'NONE',
    };

    // Apply armed relay tamper intervention if enabled
    if (
      this.demoSettings.localDemoControlsEnabled &&
      this.demoSettings.nextRelayIntervention !== 'NONE' &&
      finalEnvelope.mode !== 'LOCAL_PLAINTEXT_BASELINE'
    ) {
      const mode = this.demoSettings.nextRelayIntervention;
      this.demoSettings.nextRelayIntervention = 'NONE'; // Consume one-shot intervention

      if (mode === 'TAMPER_CIPHERTEXT') {
        finalEnvelope = tamperCiphertextBitFlip(finalEnvelope);
        this.logAppEvent(
          'RELAY_TAMPER_APPLIED',
          `Relay flipped 1 bit in ciphertext of ${finalEnvelope.envelopeId} (epoch ${finalEnvelope.header.epoch}, msg #${finalEnvelope.header.msgNum}).`
        );
      } else if (mode === 'TAMPER_HEADER') {
        finalEnvelope = tamperAuthenticatedHeader(finalEnvelope);
        this.logAppEvent(
          'RELAY_TAMPER_APPLIED',
          `Relay modified authenticated header (nonce AAD) of ${finalEnvelope.envelopeId} without recomputing GCM tag.`
        );
      } else if (mode === 'TAMPER_TAG') {
        finalEnvelope = tamperAuthTag(finalEnvelope);
        this.logAppEvent(
          'RELAY_TAMPER_APPLIED',
          `Relay corrupted 128-bit GCM authentication tag of ${finalEnvelope.envelopeId}.`
        );
      }
    } else {
      this.logAppEvent(
        'ENVELOPE_RELAYED',
        `Relayed envelope ${finalEnvelope.envelopeId} (${finalEnvelope.header.sender} -> ${finalEnvelope.header.recipient}, epoch=${finalEnvelope.header.epoch}, msg=${finalEnvelope.header.msgNum}, ${finalEnvelope.serializedEnvelopeBytes}B).`
      );
    }

    const deliveryStatus = 'RELAYED_TO_RECIPIENT';

    const insertStmt = this.db.prepare(`
      INSERT INTO relay_envelopes (
        envelope_id, conversation_id, session_id, protocol_version,
        sender, recipient, direction, epoch, msg_num,
        nonce_hex, ciphertext_hex, auth_tag_hex, mode,
        plaintext_byte_length, serialized_envelope_bytes, crypto_overhead_bytes,
        tampered_flag, delivery_status, timestamp_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    insertStmt.run(
      finalEnvelope.envelopeId,
      conversationId,
      finalEnvelope.header.sessionId,
      finalEnvelope.header.protocolVersion,
      finalEnvelope.header.sender,
      finalEnvelope.header.recipient,
      finalEnvelope.header.direction,
      finalEnvelope.header.epoch,
      finalEnvelope.header.msgNum,
      finalEnvelope.header.nonceHex,
      finalEnvelope.ciphertextHex,
      finalEnvelope.authTagHex,
      finalEnvelope.mode,
      finalEnvelope.plaintextByteLength,
      finalEnvelope.serializedEnvelopeBytes,
      finalEnvelope.cryptoOverheadBytes,
      finalEnvelope.tamperedFlag || 'NONE',
      deliveryStatus,
      finalEnvelope.timestampMs
    );

    // Record corresponding loopback packets (TCP/HTTP segments) for PacketGuard inspection
    const loopbackPackets = generateLoopbackPacketsForEnvelope(
      finalEnvelope.envelopeId,
      finalEnvelope.header.sender,
      finalEnvelope.serializedEnvelopeBytes,
      finalEnvelope.timestampMs
    );
    this.insertPackets(loopbackPackets);

    return {
      ok: true,
      status: 200,
      storedEnvelope: {
        ...finalEnvelope,
        deliveryStatus,
      },
    };
  }

  public updateEnvelopeDeliveryStatus(
    envelopeId: string,
    deliveryStatus: 'DELIVERED_VERIFIED' | 'REJECTED_AUTH_FAILED' | 'REJECTED_REPLAY'
  ): void {
    this.db
      .prepare('UPDATE relay_envelopes SET delivery_status = ? WHERE envelope_id = ?')
      .run(deliveryStatus, envelopeId);
  }

  public getConversationEnvelopes(
    conversationId: string,
    actingUser: string | null
  ): {
    ok: boolean;
    status: number;
    error?: string;
    envelopes?: Array<EncryptedEnvelope & { deliveryStatus: string }>;
  } {
    if (!this.verifyConversationMembership(conversationId, actingUser)) {
      return {
        ok: false,
        status: 403,
        error: 'Cross-conversation access denied: User is not a member of this conversation.',
      };
    }

    const rows = this.db
      .prepare(
        'SELECT * FROM relay_envelopes WHERE conversation_id = ? ORDER BY seq_id ASC'
      )
      .all(conversationId) as Array<Record<string, any>>;

    const envelopes = rows.map((r) => ({
      envelopeId: String(r.envelope_id),
      header: {
        protocolVersion: String(r.protocol_version),
        sessionId: String(r.session_id),
        sender: r.sender as 'alice' | 'bob',
        recipient: r.recipient as 'alice' | 'bob',
        direction: r.direction as 'A2B' | 'B2A',
        epoch: Number(r.epoch),
        msgNum: Number(r.msg_num),
        nonceHex: String(r.nonce_hex),
      },
      mode: r.mode as EncryptedEnvelope['mode'],
      ciphertextHex: String(r.ciphertext_hex),
      authTagHex: String(r.auth_tag_hex),
      timestampMs: Number(r.timestamp_ms),
      plaintextByteLength: Number(r.plaintext_byte_length),
      serializedEnvelopeBytes: Number(r.serialized_envelope_bytes),
      cryptoOverheadBytes: Number(r.crypto_overhead_bytes),
      tamperedFlag: r.tampered_flag as EncryptedEnvelope['tamperedFlag'],
      deliveryStatus: String(r.delivery_status),
    }));

    return { ok: true, status: 200, envelopes };
  }

  /**
   * Inspects raw SQLite database contents for Test #11 (verifying that known test plaintext
   * is completely absent from relay storage and application logs in encrypted mode).
   */
  public dumpRawRelayStorageForAudit(): string {
    const envelopes = this.db.prepare('SELECT * FROM relay_envelopes').all();
    const convs = this.db.prepare('SELECT * FROM conversations').all();
    return JSON.stringify({
      envelopes,
      convs,
      applicationEventLog: this.applicationEventLog,
    });
  }

  public insertPackets(packets: PacketMetadataRecord[]): void {
    const insertPkt = this.db.prepare(`
      INSERT OR REPLACE INTO packet_metadata (
        packet_id, timestamp_ms, source_type, scenario_name, interface_name,
        src_ip, dst_ip, src_port, dst_port, protocol, captured_bytes,
        tcp_flags, arp_sender_mac, arp_sender_ip, arp_operation,
        dns_query_name, dns_query_type, linked_envelope_id, notes
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const tx = this.db.transaction((items: PacketMetadataRecord[]) => {
      for (const p of items) {
        insertPkt.run(
          p.packetId,
          p.timestampMs,
          p.sourceType,
          p.scenarioName,
          p.interfaceName,
          p.srcIp,
          p.dstIp,
          p.srcPort,
          p.dstPort,
          p.protocol,
          p.capturedBytes,
          p.tcpFlags ?? null,
          p.arpSenderMac ?? null,
          p.arpSenderIp ?? null,
          p.arpOperation ?? null,
          p.dnsQueryName ?? null,
          p.dnsQueryType ?? null,
          p.linkedEnvelopeId ?? null,
          p.notes ?? null
        );
      }
    });
    tx(packets);
    this.recomputeAlerts();
  }

  public loadScenarioPackets(scenarioId: ScenarioId, clearExisting = true): {
    packets: PacketMetadataRecord[];
    alerts: HeuristicAlert[];
  } {
    if (clearExisting) {
      this.db.prepare('DELETE FROM packet_metadata').run();
      this.db.prepare('DELETE FROM alerts').run();
    }
    const scenarioPackets = buildClassroomScenarioPackets(scenarioId, Date.now() - 15000);
    this.insertPackets(scenarioPackets);
    return {
      packets: this.getPackets(),
      alerts: this.getAlerts(),
    };
  }

  public getPackets(): PacketMetadataRecord[] {
    const rows = this.db
      .prepare('SELECT * FROM packet_metadata ORDER BY timestamp_ms ASC, seq_id ASC')
      .all() as Array<Record<string, any>>;

    return rows.map((r) => ({
      packetId: String(r.packet_id),
      timestampMs: Number(r.timestamp_ms),
      sourceType: r.source_type as PacketMetadataRecord['sourceType'],
      scenarioName: String(r.scenario_name),
      interfaceName: String(r.interface_name),
      srcIp: String(r.src_ip),
      dstIp: String(r.dst_ip),
      srcPort: r.src_port !== null ? Number(r.src_port) : null,
      dstPort: r.dst_port !== null ? Number(r.dst_port) : null,
      protocol: r.protocol as PacketMetadataRecord['protocol'],
      capturedBytes: Number(r.captured_bytes),
      tcpFlags: r.tcp_flags ? String(r.tcp_flags) : undefined,
      arpSenderMac: r.arp_sender_mac ? String(r.arp_sender_mac) : undefined,
      arpSenderIp: r.arp_sender_ip ? String(r.arp_sender_ip) : undefined,
      arpOperation: r.arp_operation ? (r.arp_operation as 'REQUEST' | 'REPLY') : undefined,
      dnsQueryName: r.dns_query_name ? String(r.dns_query_name) : undefined,
      dnsQueryType: r.dns_query_type ? String(r.dns_query_type) : undefined,
      linkedEnvelopeId: r.linked_envelope_id ? String(r.linked_envelope_id) : undefined,
      notes: r.notes ? String(r.notes) : undefined,
    }));
  }

  public recomputeAlerts(): HeuristicAlert[] {
    const packets = this.getPackets();
    const evaluated = evaluatePacketGuardRules(packets, this.ruleConfig);

    this.db.prepare('DELETE FROM alerts').run();
    const insertAlert = this.db.prepare(`
      INSERT INTO alerts (
        alert_id, rule_id, title, severity, timestamp_ms,
        source_type, scenario_name, src_ip, dst_ip,
        observed_value, threshold_value, evidence_summary, benign_explanation, sample_packet_ids_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const tx = this.db.transaction((items: HeuristicAlert[]) => {
      for (const a of items) {
        insertAlert.run(
          a.alertId,
          a.ruleId,
          a.title,
          a.severity,
          a.timestampMs,
          a.sourceType,
          a.scenarioName,
          a.srcIp,
          a.dstIp,
          a.observedValue,
          a.thresholdValue,
          a.evidenceSummary,
          a.benignExplanation,
          JSON.stringify(a.samplePacketIds)
        );
      }
    });
    tx(evaluated);
    return evaluated;
  }

  public getAlerts(): HeuristicAlert[] {
    const rows = this.db
      .prepare('SELECT * FROM alerts ORDER BY timestamp_ms DESC')
      .all() as Array<Record<string, any>>;

    return rows.map((r) => ({
      alertId: String(r.alert_id),
      ruleId: r.rule_id as HeuristicAlert['ruleId'],
      title: String(r.title),
      severity: r.severity as HeuristicAlert['severity'],
      timestampMs: Number(r.timestamp_ms),
      sourceType: r.source_type as HeuristicAlert['sourceType'],
      scenarioName: String(r.scenario_name),
      srcIp: String(r.src_ip),
      dstIp: String(r.dst_ip),
      observedValue: String(r.observed_value),
      thresholdValue: String(r.threshold_value),
      evidenceSummary: String(r.evidence_summary),
      benignExplanation: String(r.benign_explanation),
      samplePacketIds: JSON.parse(String(r.sample_packet_ids_json || '[]')),
    }));
  }

  public resetAll(): void {
    this.db.prepare('DELETE FROM relay_envelopes').run();
    this.db.prepare('DELETE FROM packet_metadata').run();
    this.db.prepare('DELETE FROM alerts').run();
    this.demoSettings.nextRelayIntervention = 'NONE';
    this.applicationEventLog = [];
    this.loadScenarioPackets('BENIGN_BASELINE_ALL');
  }

  /**
   * Probes whether TShark is installed and accessible for live packet capture.
   * Gracefully falls back with clear diagnostics when TShark or capture permissions are absent.
   */
  public probeLiveCaptureEnvironment(customTsharkBinary = 'tshark'): LiveCaptureStatus {
    try {
      const versionOutput = execFileSync(customTsharkBinary, ['--version'], {
        encoding: 'utf8',
        timeout: 1500,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      const firstLine = versionOutput.split('\n')[0]?.trim() || 'TShark detected';

      try {
        const ifacesOutput = execFileSync(customTsharkBinary, ['-D'], {
          encoding: 'utf8',
          timeout: 1500,
          stdio: ['ignore', 'pipe', 'pipe'],
        });
        const interfaces = ifacesOutput
          .split('\n')
          .map((l) => l.trim())
          .filter(Boolean);

        return {
          tsharkInstalled: true,
          tsharkVersion: firstLine,
          capturePermissionGranted: interfaces.length > 0,
          activeCaptureMode: 'RECORDED_OR_SYNTHETIC',
          selectedInterface: interfaces[0] || 'lo0 (Loopback)',
          availableInterfaces: interfaces.length > 0 ? interfaces : ['lo0 (Loopback)', 'eth0'],
          fallbackReason:
            'TShark is installed. Use the separate local capture_worker.py worker to stream live interface metadata.',
          boundedBufferCapacity: 2048,
          droppedPacketsCount: 0,
        };
      } catch {
        return {
          tsharkInstalled: true,
          tsharkVersion: firstLine,
          capturePermissionGranted: false,
          activeCaptureMode: 'RECORDED_OR_SYNTHETIC',
          selectedInterface: 'lo0 (Loopback)',
          availableInterfaces: ['lo0 (Loopback)', 'eth0 (Simulated/Recorded)'],
          fallbackReason:
            'TShark binary found, but current non-root user lacks dumpcap/BPF packet capture permissions. Operating in Recorded Capture & Synthetic Fixture mode.',
          boundedBufferCapacity: 2048,
          droppedPacketsCount: 0,
        };
      }
    } catch {
      return {
        tsharkInstalled: false,
        tsharkVersion: null,
        capturePermissionGranted: false,
        activeCaptureMode: 'RECORDED_OR_SYNTHETIC',
        selectedInterface: 'lo0 (Recorded Loopback)',
        availableInterfaces: ['lo0 (Recorded Loopback)', 'eth0 (Recorded Lab Trace)'],
        fallbackReason:
          'TShark/Pyshark binary not present in this environment (or running inside a hosted container without raw socket privileges). Gracefully operating in Recorded PCAP & Synthetic Fixture mode.',
        boundedBufferCapacity: 2048,
        droppedPacketsCount: 0,
      };
    }
  }
}
