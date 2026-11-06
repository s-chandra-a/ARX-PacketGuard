export type DataSourceType =
  | 'RECORDED_PCAP_TRACE'
  | 'SYNTHETIC_FIXTURE'
  | 'LIVE_CAPTURE_WORKER';

export type PacketProtocol = 'TCP' | 'UDP' | 'DNS' | 'ARP' | 'HTTP' | 'TLS';

export interface PacketMetadataRecord {
  packetId: string;
  timestampMs: number; // Capture timestamp in ms (used consistently for window & rate calculations)
  sourceType: DataSourceType;
  scenarioName: string;
  interfaceName: string;
  srcIp: string;
  dstIp: string;
  srcPort: number | null;
  dstPort: number | null;
  protocol: PacketProtocol;
  capturedBytes: number;
  tcpFlags?: string; // e.g., "SYN", "SYN,ACK", "ACK", "PSH,ACK", "FIN,ACK", "RST"
  arpSenderMac?: string;
  arpSenderIp?: string;
  arpOperation?: 'REQUEST' | 'REPLY';
  dnsQueryName?: string;
  dnsQueryType?: string;
  linkedEnvelopeId?: string; // Optional correlation ID to illustrate 1 app message -> multiple packets
  notes?: string;
}

export interface DetectionRuleConfig {
  // Rule 1: Possible Port Scan
  portScanWindowSeconds: number;
  portScanDistinctPortsThreshold: number;

  // Rule 2: Possible SYN Flood (flow-correlated)
  synFloodWindowSeconds: number;
  synFloodCountThreshold: number;
  synFloodMaxCompletionRatio: number;

  // Rule 3: Possible ARP Mapping Conflict
  arpWindowSeconds: number;
  arpDistinctMacThreshold: number;

  // Rule 4: Suspicious DNS Activity
  dnsWindowSeconds: number;
  dnsMaxLabelLength: number;
  dnsMaxLabelEntropy: number;
  dnsQueryRateThreshold: number;

  // Cooldown suppression
  alertCooldownSeconds: number;
}

export type RuleId =
  | 'POSSIBLE_PORT_SCAN'
  | 'POSSIBLE_SYN_FLOOD'
  | 'POSSIBLE_ARP_CONFLICT'
  | 'SUSPICIOUS_DNS_ACTIVITY';

export interface HeuristicAlert {
  alertId: string;
  ruleId: RuleId;
  title: string;
  severity: 'WARNING' | 'ELEVATED';
  timestampMs: number;
  sourceType: DataSourceType;
  scenarioName: string;
  srcIp: string;
  dstIp: string;
  observedValue: string;
  thresholdValue: string;
  evidenceSummary: string;
  benignExplanation: string;
  samplePacketIds: string[];
}

export interface TrafficWindowMetrics {
  totalPackets: number;
  totalCapturedBytes: number;
  incomingBytesClient: number;
  outgoingBytesClient: number;
  packetsPerSecond: number;
  bytesPerSecond: number;
  protocolBreakdown: Record<PacketProtocol, number>;
  timeSeriesBuckets: Array<{
    bucketTimestampMs: number;
    label: string;
    incomingBytes: number;
    outgoingBytes: number;
    packetCount: number;
    pps: number;
  }>;
}

export const DEFAULT_RULE_CONFIG: DetectionRuleConfig = {
  portScanWindowSeconds: 10,
  portScanDistinctPortsThreshold: 20,

  synFloodWindowSeconds: 10,
  synFloodCountThreshold: 25,
  synFloodMaxCompletionRatio: 0.25,

  arpWindowSeconds: 60,
  arpDistinctMacThreshold: 2,

  dnsWindowSeconds: 10,
  dnsMaxLabelLength: 32,
  dnsMaxLabelEntropy: 3.8,
  dnsQueryRateThreshold: 20,

  alertCooldownSeconds: 15,
};

/**
 * Computes Shannon entropy in bits per character (0 to ~4.75 for base36/hex/alphanumeric).
 */
export function computeShannonEntropy(input: string): number {
  if (!input || input.length === 0) return 0;
  const counts: Record<string, number> = {};
  for (const ch of input) {
    counts[ch] = (counts[ch] || 0) + 1;
  }
  const len = input.length;
  let entropy = 0;
  for (const ch of Object.keys(counts)) {
    const p = counts[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(2));
}

/**
 * Evaluates a stream of packet metadata records using capture timestamps consistently
 * across sliding windows, flow-correlated TCP handshake tracking, and alert cooldown suppression.
 */
export function evaluatePacketGuardRules(
  packets: PacketMetadataRecord[],
  config: DetectionRuleConfig = DEFAULT_RULE_CONFIG
): HeuristicAlert[] {
  if (packets.length === 0) return [];

  const sorted = [...packets].sort((a, b) => a.timestampMs - b.timestampMs);
  const alerts: HeuristicAlert[] = [];
  const lastAlertTimeByKey: Record<string, number> = {};

  function canEmitAlert(ruleId: RuleId, srcIp: string, dstIp: string, ts: number): boolean {
    const key = `${ruleId}|${srcIp}|${dstIp}`;
    const prev = lastAlertTimeByKey[key];
    if (prev !== undefined && ts - prev < config.alertCooldownSeconds * 1000) {
      return false;
    }
    lastAlertTimeByKey[key] = ts;
    return true;
  }

  for (let i = 0; i < sorted.length; i++) {
    const current = sorted[i];
    const nowTs = current.timestampMs;

    // -------------------------------------------------------------------------
    // Rule 1: Possible Port Scan (sliding window over [nowTs - window, nowTs])
    // -------------------------------------------------------------------------
    if (current.dstPort !== null && (current.protocol === 'TCP' || current.protocol === 'UDP')) {
      const windowStart = nowTs - config.portScanWindowSeconds * 1000;
      const distinctPorts = new Set<number>();
      const sampleIds: string[] = [];

      for (let j = i; j >= 0; j--) {
        const p = sorted[j];
        if (p.timestampMs < windowStart) break;
        if (p.srcIp === current.srcIp && p.dstIp === current.dstIp && p.dstPort !== null) {
          distinctPorts.add(p.dstPort);
          if (sampleIds.length < 6) sampleIds.push(p.packetId);
        }
      }

      if (
        distinctPorts.size >= config.portScanDistinctPortsThreshold &&
        canEmitAlert('POSSIBLE_PORT_SCAN', current.srcIp, current.dstIp, nowTs)
      ) {
        const portSample = Array.from(distinctPorts).slice(0, 8).join(', ');
        alerts.push({
          alertId: `alert-ps-${nowTs}-${alerts.length}`,
          ruleId: 'POSSIBLE_PORT_SCAN',
          title: 'Possible TCP/UDP Port Scan Activity',
          severity: 'WARNING',
          timestampMs: nowTs,
          sourceType: current.sourceType,
          scenarioName: current.scenarioName,
          srcIp: current.srcIp,
          dstIp: current.dstIp,
          observedValue: `${distinctPorts.size} distinct ports in ${config.portScanWindowSeconds}s`,
          thresholdValue: `>= ${config.portScanDistinctPortsThreshold} ports / ${config.portScanWindowSeconds}s`,
          evidenceSummary: `Host ${current.srcIp} probed ${distinctPorts.size} distinct destination ports on ${current.dstIp} (sampled ports: ${portSample}...).`,
          benignExplanation:
            'Could be caused by rapid microservice discovery, peer-to-peer NAT traversal, or parallel health-check probes.',
          samplePacketIds: sampleIds,
        });
      }
    }

    // -------------------------------------------------------------------------
    // Rule 2: Possible SYN Flood (flow-correlated 3-way handshake verification)
    // -------------------------------------------------------------------------
    if (current.protocol === 'TCP' && current.tcpFlags === 'SYN') {
      const windowStart = nowTs - config.synFloodWindowSeconds * 1000;
      // Track 4-tuple flows initiated toward current.dstIp within the window
      // A flow is ONLY completed if we see:
      // 1) SYN (client -> server)
      // 2) SYN,ACK (server -> client on matching ports)
      // 3) ACK (client -> server on matching ports)
      // Uncorrelated arbitrary ACK packets on other tuples are never counted as completed handshakes.
      const flowState: Record<
        string,
        { hasSyn: boolean; hasSynAck: boolean; hasFinalAck: boolean; packetId: string }
      > = {};

      for (let j = 0; j <= i; j++) {
        const p = sorted[j];
        if (p.timestampMs < windowStart) continue;
        if (p.protocol !== 'TCP' || p.srcPort === null || p.dstPort === null) continue;

        if (p.dstIp === current.dstIp && p.tcpFlags === 'SYN') {
          const tupleKey = `${p.srcIp}:${p.srcPort}->${p.dstIp}:${p.dstPort}`;
          flowState[tupleKey] = {
            hasSyn: true,
            hasSynAck: false,
            hasFinalAck: false,
            packetId: p.packetId,
          };
        } else if (p.srcIp === current.dstIp && p.tcpFlags === 'SYN,ACK') {
          const reverseKey = `${p.dstIp}:${p.dstPort}->${p.srcIp}:${p.srcPort}`;
          if (flowState[reverseKey]?.hasSyn) {
            flowState[reverseKey].hasSynAck = true;
          }
        } else if (p.dstIp === current.dstIp && p.tcpFlags === 'ACK') {
          const tupleKey = `${p.srcIp}:${p.srcPort}->${p.dstIp}:${p.dstPort}`;
          if (flowState[tupleKey]?.hasSyn && flowState[tupleKey]?.hasSynAck) {
            flowState[tupleKey].hasFinalAck = true;
          }
        }
      }

      const flows = Object.values(flowState);
      const totalSyns = flows.length;
      const completedFlows = flows.filter((f) => f.hasFinalAck).length;
      const completionRatio = totalSyns > 0 ? completedFlows / totalSyns : 1;

      if (
        totalSyns >= config.synFloodCountThreshold &&
        completionRatio <= config.synFloodMaxCompletionRatio &&
        canEmitAlert('POSSIBLE_SYN_FLOOD', current.srcIp, current.dstIp, nowTs)
      ) {
        alerts.push({
          alertId: `alert-syn-${nowTs}-${alerts.length}`,
          ruleId: 'POSSIBLE_SYN_FLOOD',
          title: 'Possible Uncompleted TCP SYN Flood',
          severity: 'ELEVATED',
          timestampMs: nowTs,
          sourceType: current.sourceType,
          scenarioName: current.scenarioName,
          srcIp: current.srcIp,
          dstIp: current.dstIp,
          observedValue: `${totalSyns} SYNs, ${(completionRatio * 100).toFixed(1)}% completed (${completedFlows}/${totalSyns})`,
          thresholdValue: `>= ${config.synFloodCountThreshold} SYNs & <= ${(
            config.synFloodMaxCompletionRatio * 100
          ).toFixed(0)}% 3-way completion`,
          evidenceSummary: `Observed ${totalSyns} TCP SYN connection attempts to ${current.dstIp} within ${config.synFloodWindowSeconds}s with only ${completedFlows} correlated 3-way handshakes completed.`,
          benignExplanation:
            'May occur when a legitimate backend service is temporarily unreachable or dropping SYN-ACK responses under sudden load.',
          samplePacketIds: flows.slice(0, 6).map((f) => f.packetId),
        });
      }
    }

    // -------------------------------------------------------------------------
    // Rule 3: Possible ARP Mapping Conflict
    // -------------------------------------------------------------------------
    if (current.protocol === 'ARP' && current.arpSenderIp && current.arpSenderMac) {
      const windowStart = nowTs - config.arpWindowSeconds * 1000;
      const macsForIp = new Set<string>();
      const sampleIds: string[] = [];

      for (let j = i; j >= 0; j--) {
        const p = sorted[j];
        if (p.timestampMs < windowStart) break;
        if (
          p.protocol === 'ARP' &&
          p.arpSenderIp === current.arpSenderIp &&
          p.arpSenderMac
        ) {
          macsForIp.add(p.arpSenderMac.toUpperCase());
          if (sampleIds.length < 6) sampleIds.push(p.packetId);
        }
      }

      if (
        macsForIp.size >= config.arpDistinctMacThreshold &&
        canEmitAlert('POSSIBLE_ARP_CONFLICT', current.arpSenderIp, 'Broadcast/LAN', nowTs)
      ) {
        const macList = Array.from(macsForIp).join(' vs. ');
        alerts.push({
          alertId: `alert-arp-${nowTs}-${alerts.length}`,
          ruleId: 'POSSIBLE_ARP_CONFLICT',
          title: 'Possible ARP IP-to-MAC Mapping Conflict',
          severity: 'ELEVATED',
          timestampMs: nowTs,
          sourceType: current.sourceType,
          scenarioName: current.scenarioName,
          srcIp: current.arpSenderIp,
          dstIp: current.dstIp,
          observedValue: `${macsForIp.size} MAC addresses (${macList})`,
          thresholdValue: `>= ${config.arpDistinctMacThreshold} distinct MACs for 1 IP in ${config.arpWindowSeconds}s`,
          evidenceSummary: `IPv4 address ${current.arpSenderIp} was announced by ${macsForIp.size} different hardware MAC addresses (${macList}) within ${config.arpWindowSeconds}s.`,
          benignExplanation:
            'Legitimate causes include VRRP/HSRP gateway failover, NIC bonding/failover, or virtual machine live migration.',
          samplePacketIds: sampleIds,
        });
      }
    }

    // -------------------------------------------------------------------------
    // Rule 4: Suspicious DNS Activity (Label length, Shannon entropy, or query rate)
    // -------------------------------------------------------------------------
    if (current.protocol === 'DNS' && current.dnsQueryName) {
      const labels = current.dnsQueryName.split('.');
      const leftmostLabel = labels[0] || '';
      const labelLen = leftmostLabel.length;
      const labelEntropy = labelLen >= 14 ? computeShannonEntropy(leftmostLabel) : 0;

      const windowStart = nowTs - config.dnsWindowSeconds * 1000;
      const recentDnsPackets: PacketMetadataRecord[] = [];
      for (let j = i; j >= 0; j--) {
        const p = sorted[j];
        if (p.timestampMs < windowStart) break;
        if (p.protocol === 'DNS' && p.srcIp === current.srcIp) {
          recentDnsPackets.push(p);
        }
      }

      const isLongLabel = labelLen >= config.dnsMaxLabelLength;
      const isHighEntropy = labelLen >= 14 && labelEntropy >= config.dnsMaxLabelEntropy;
      const isHighRate = recentDnsPackets.length >= config.dnsQueryRateThreshold;

      if (
        (isLongLabel || isHighEntropy || isHighRate) &&
        canEmitAlert('SUSPICIOUS_DNS_ACTIVITY', current.srcIp, current.dstIp, nowTs)
      ) {
        const reasons: string[] = [];
        if (isLongLabel) reasons.push(`label length ${labelLen} chars`);
        if (isHighEntropy) reasons.push(`Shannon entropy ${labelEntropy} bits/char`);
        if (isHighRate)
          reasons.push(`${recentDnsPackets.length} queries in ${config.dnsWindowSeconds}s`);

        alerts.push({
          alertId: `alert-dns-${nowTs}-${alerts.length}`,
          ruleId: 'SUSPICIOUS_DNS_ACTIVITY',
          title: 'Suspicious DNS Query Pattern',
          severity: 'WARNING',
          timestampMs: nowTs,
          sourceType: current.sourceType,
          scenarioName: current.scenarioName,
          srcIp: current.srcIp,
          dstIp: current.dstIp,
          observedValue: reasons.join(', '),
          thresholdValue: `Len >= ${config.dnsMaxLabelLength} | Entropy >= ${config.dnsMaxLabelEntropy} | Rate >= ${config.dnsQueryRateThreshold}/${config.dnsWindowSeconds}s`,
          evidenceSummary: `DNS query "${current.dnsQueryName}" from ${current.srcIp} triggered heuristic indicators: ${reasons.join('; ')}.`,
          benignExplanation:
            'Often triggered by legitimate CDN edge hostnames (CloudFront/Akamai), anti-spam DKIM/SPF lookups, or cloud load-balancer telemetry.',
          samplePacketIds: recentDnsPackets.slice(0, 6).map((p) => p.packetId),
        });
      }
    }
  }

  return alerts;
}

/**
 * Computes traffic volume, byte rates, packets per second, and protocol breakdown
 * using the packet capture timestamps consistently.
 *
 * Direction convention on loopback (`lo0` / `127.0.0.1`):
 * - Alice client uses ephemeral port `54110`, Bob client uses `54120`, Relay uses `3000`.
 * - Relative to the selected perspective (`'alice'` | `'bob'` | `'relay'`):
 *   - `outgoingBytesClient`: packets sent FROM the selected endpoint's IP/port.
 *   - `incomingBytesClient`: packets sent TO the selected endpoint's IP/port.
 */
export function computeTrafficMetrics(
  packets: PacketMetadataRecord[],
  perspective: 'alice' | 'bob' | 'relay' = 'alice'
): TrafficWindowMetrics {
  const protocolBreakdown: Record<PacketProtocol, number> = {
    TCP: 0,
    UDP: 0,
    DNS: 0,
    ARP: 0,
    HTTP: 0,
    TLS: 0,
  };

  if (packets.length === 0) {
    return {
      totalPackets: 0,
      totalCapturedBytes: 0,
      incomingBytesClient: 0,
      outgoingBytesClient: 0,
      packetsPerSecond: 0,
      bytesPerSecond: 0,
      protocolBreakdown,
      timeSeriesBuckets: [],
    };
  }

  const sorted = [...packets].sort((a, b) => a.timestampMs - b.timestampMs);
  let totalCapturedBytes = 0;
  let incomingBytesClient = 0;
  let outgoingBytesClient = 0;

  const isEndpointMatch = (ip: string, port: number | null): boolean => {
    if (perspective === 'alice') {
      return port === 54110 || ip === '10.0.1.10';
    }
    if (perspective === 'bob') {
      return port === 54120 || ip === '10.0.1.20';
    }
    return port === 3000 || ip === '10.0.1.100';
  };

  for (const pkt of sorted) {
    totalCapturedBytes += pkt.capturedBytes;
    protocolBreakdown[pkt.protocol] = (protocolBreakdown[pkt.protocol] || 0) + 1;

    if (isEndpointMatch(pkt.srcIp, pkt.srcPort)) {
      outgoingBytesClient += pkt.capturedBytes;
    } else if (isEndpointMatch(pkt.dstIp, pkt.dstPort)) {
      incomingBytesClient += pkt.capturedBytes;
    } else {
      // Background LAN traffic: attribute incoming if broadcast/targeted to subnet
      incomingBytesClient += pkt.capturedBytes;
    }
  }

  const minTs = sorted[0].timestampMs;
  const maxTs = sorted[sorted.length - 1].timestampMs;
  const spanSeconds = Math.max(1, (maxTs - minTs) / 1000);

  const packetsPerSecond = Number((sorted.length / spanSeconds).toFixed(2));
  const bytesPerSecond = Number((totalCapturedBytes / spanSeconds).toFixed(1));

  // Build 1-second buckets across the capture window (up to 20 buckets)
  const bucketSpanMs = Math.max(1000, Math.ceil((maxTs - minTs + 1) / 12));
  const bucketMap = new Map<
    number,
    { incomingBytes: number; outgoingBytes: number; packetCount: number }
  >();

  for (const pkt of sorted) {
    const bucketIdx = Math.floor((pkt.timestampMs - minTs) / bucketSpanMs);
    const bucketTs = minTs + bucketIdx * bucketSpanMs;
    const entry = bucketMap.get(bucketTs) || {
      incomingBytes: 0,
      outgoingBytes: 0,
      packetCount: 0,
    };
    entry.packetCount += 1;
    if (isEndpointMatch(pkt.srcIp, pkt.srcPort)) {
      entry.outgoingBytes += pkt.capturedBytes;
    } else {
      entry.incomingBytes += pkt.capturedBytes;
    }
    bucketMap.set(bucketTs, entry);
  }

  const timeSeriesBuckets = Array.from(bucketMap.entries())
    .sort((a, b) => a[0] - b[0])
    .map(([bucketTs, val]) => {
      const relSec = ((bucketTs - minTs) / 1000).toFixed(1);
      return {
        bucketTimestampMs: bucketTs,
        label: `+${relSec}s`,
        incomingBytes: val.incomingBytes,
        outgoingBytes: val.outgoingBytes,
        packetCount: val.packetCount,
        pps: Number((val.packetCount / (bucketSpanMs / 1000)).toFixed(2)),
      };
    });

  return {
    totalPackets: sorted.length,
    totalCapturedBytes,
    incomingBytesClient,
    outgoingBytesClient,
    packetsPerSecond,
    bytesPerSecond,
    protocolBreakdown,
    timeSeriesBuckets,
  };
}

/**
 * Generates realistic loopback TCP/HTTP packet metadata corresponding to an application
 * message relay event so students can observe why 1 application message != 1 network packet
 * (e.g., TCP PSH,ACK request segment + HTTP 200 OK response + TCP ACK).
 */
export function generateLoopbackPacketsForEnvelope(
  envelopeId: string,
  sender: 'alice' | 'bob',
  serializedEnvelopeBytes: number,
  timestampMs: number
): PacketMetadataRecord[] {
  const clientPort = sender === 'alice' ? 54110 : 54120;
  const relayPort = 3000;
  const httpHeaderBytes = 218;
  const tcpIpLoopbackHeaderBytes = 44; // 20B IPv4 + 20B TCP + 4B Null/Loopback encapsulation

  const requestPacketBytes =
    serializedEnvelopeBytes + httpHeaderBytes + tcpIpLoopbackHeaderBytes;
  const responsePacketBytes = 165 + tcpIpLoopbackHeaderBytes;

  return [
    {
      packetId: `pkt-${envelopeId}-1`,
      timestampMs,
      sourceType: 'RECORDED_PCAP_TRACE',
      scenarioName: 'Loopback ARX Relay Trace (lo0)',
      interfaceName: 'lo0',
      srcIp: '127.0.0.1',
      dstIp: '127.0.0.1',
      srcPort: clientPort,
      dstPort: relayPort,
      protocol: 'HTTP',
      capturedBytes: requestPacketBytes,
      tcpFlags: 'PSH,ACK',
      linkedEnvelopeId: envelopeId,
      notes: `HTTP POST /api/relay/send carrying envelope (${serializedEnvelopeBytes}B payload + ${httpHeaderBytes}B HTTP + ${tcpIpLoopbackHeaderBytes}B TCP/IP/lo0)`,
    },
    {
      packetId: `pkt-${envelopeId}-2`,
      timestampMs: timestampMs + 2,
      sourceType: 'RECORDED_PCAP_TRACE',
      scenarioName: 'Loopback ARX Relay Trace (lo0)',
      interfaceName: 'lo0',
      srcIp: '127.0.0.1',
      dstIp: '127.0.0.1',
      srcPort: relayPort,
      dstPort: clientPort,
      protocol: 'HTTP',
      capturedBytes: responsePacketBytes,
      tcpFlags: 'PSH,ACK',
      linkedEnvelopeId: envelopeId,
      notes: 'HTTP 200 OK relay receipt acknowledgement',
    },
    {
      packetId: `pkt-${envelopeId}-3`,
      timestampMs: timestampMs + 3,
      sourceType: 'RECORDED_PCAP_TRACE',
      scenarioName: 'Loopback ARX Relay Trace (lo0)',
      interfaceName: 'lo0',
      srcIp: '127.0.0.1',
      dstIp: '127.0.0.1',
      srcPort: clientPort,
      dstPort: relayPort,
      protocol: 'TCP',
      capturedBytes: tcpIpLoopbackHeaderBytes,
      tcpFlags: 'ACK',
      linkedEnvelopeId: envelopeId,
      notes: 'TCP ACK segment completing relay transaction',
    },
  ];
}

/**
 * Classroom Preset Scenarios (Both Benign Baselines and Suspicious Heuristic Triggers
 * for all 4 required rules, clearly distinguishing RECORDED_PCAP_TRACE vs SYNTHETIC_FIXTURE).
 */
export type ScenarioId =
  | 'BENIGN_BASELINE_ALL'
  | 'SUSPICIOUS_PORT_SCAN'
  | 'SUSPICIOUS_SYN_FLOOD'
  | 'SUSPICIOUS_ARP_CONFLICT'
  | 'SUSPICIOUS_DNS_TUNNELING'
  | 'COMBINED_CLASSROOM_DEMO';

export function buildClassroomScenarioPackets(
  scenarioId: ScenarioId,
  baseTimestampMs = 1762420000000
): PacketMetadataRecord[] {
  const packets: PacketMetadataRecord[] = [];

  if (scenarioId === 'BENIGN_BASELINE_ALL') {
    // 1. Benign TCP/HTTP flows with completed 3-way handshakes (4 ports only, well below 20 threshold)
    const benignPorts = [80, 443, 3000, 8080];
    benignPorts.forEach((port, idx) => {
      const t = baseTimestampMs + idx * 400;
      const sport = 52000 + idx;
      packets.push(
        {
          packetId: `benign-tcp-syn-${idx}`,
          timestampMs: t,
          sourceType: 'RECORDED_PCAP_TRACE',
          scenarioName: 'Benign Lab Baseline (Recorded PCAP)',
          interfaceName: 'eth0',
          srcIp: '10.0.1.10',
          dstIp: '10.0.1.100',
          srcPort: sport,
          dstPort: port,
          protocol: 'TCP',
          capturedBytes: 74,
          tcpFlags: 'SYN',
          notes: 'Normal TCP connection initiation',
        },
        {
          packetId: `benign-tcp-synack-${idx}`,
          timestampMs: t + 5,
          sourceType: 'RECORDED_PCAP_TRACE',
          scenarioName: 'Benign Lab Baseline (Recorded PCAP)',
          interfaceName: 'eth0',
          srcIp: '10.0.1.100',
          dstIp: '10.0.1.10',
          srcPort: port,
          dstPort: sport,
          protocol: 'TCP',
          capturedBytes: 74,
          tcpFlags: 'SYN,ACK',
          notes: 'Server SYN,ACK response',
        },
        {
          packetId: `benign-tcp-ack-${idx}`,
          timestampMs: t + 9,
          sourceType: 'RECORDED_PCAP_TRACE',
          scenarioName: 'Benign Lab Baseline (Recorded PCAP)',
          interfaceName: 'eth0',
          srcIp: '10.0.1.10',
          dstIp: '10.0.1.100',
          srcPort: sport,
          dstPort: port,
          protocol: 'TCP',
          capturedBytes: 66,
          tcpFlags: 'ACK',
          notes: 'Completed 3-way handshake ACK',
        }
      );
    });

    // 2. Benign consistent ARP announcements (1 IP -> 1 consistent MAC)
    for (let i = 0; i < 3; i++) {
      packets.push({
        packetId: `benign-arp-${i}`,
        timestampMs: baseTimestampMs + 2000 + i * 500,
        sourceType: 'RECORDED_PCAP_TRACE',
        scenarioName: 'Benign Lab Baseline (Recorded PCAP)',
        interfaceName: 'eth0',
        srcIp: '10.0.1.1',
        dstIp: '255.255.255.255',
        srcPort: null,
        dstPort: null,
        protocol: 'ARP',
        capturedBytes: 60,
        arpOperation: 'REPLY',
        arpSenderIp: '10.0.1.1',
        arpSenderMac: '00:1A:2B:3C:4D:5E',
        notes: 'Consistent gateway ARP cache refresh',
      });
    }

    // 3. Benign standard DNS queries (short low-entropy labels, low rate)
    const benignDomains = ['relay.arx.local', 'docs.university.edu', 'ntp.ubuntu.com'];
    benignDomains.forEach((domain, idx) => {
      packets.push({
        packetId: `benign-dns-${idx}`,
        timestampMs: baseTimestampMs + 3500 + idx * 600,
        sourceType: 'RECORDED_PCAP_TRACE',
        scenarioName: 'Benign Lab Baseline (Recorded PCAP)',
        interfaceName: 'eth0',
        srcIp: '10.0.1.10',
        dstIp: '10.0.1.53',
        srcPort: 55100 + idx,
        dstPort: 53,
        protocol: 'DNS',
        capturedBytes: 92,
        dnsQueryName: domain,
        dnsQueryType: 'A',
        notes: 'Standard hostname lookup',
      });
    });

    return packets;
  }

  if (scenarioId === 'SUSPICIOUS_PORT_SCAN' || scenarioId === 'COMBINED_CLASSROOM_DEMO') {
    // 24 distinct destination ports from 10.0.1.88 -> 10.0.1.100 within 4.8 seconds
    const scannedPorts = [
      21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433,
      1521, 3000, 3306, 3389, 5432, 5900, 6379, 8080,
    ];
    scannedPorts.forEach((dstPort, idx) => {
      packets.push({
        packetId: `scan-pkt-${idx}`,
        timestampMs: baseTimestampMs + idx * 180,
        sourceType: 'SYNTHETIC_FIXTURE',
        scenarioName: 'Synthetic Port Sweep Fixture',
        interfaceName: 'eth0',
        srcIp: '10.0.1.88',
        dstIp: '10.0.1.100',
        srcPort: 49100 + idx,
        dstPort,
        protocol: 'TCP',
        capturedBytes: 60,
        tcpFlags: 'SYN',
        notes: `Sequential port probe toward TCP/${dstPort}`,
      });
    });
  }

  if (scenarioId === 'SUSPICIOUS_SYN_FLOOD' || scenarioId === 'COMBINED_CLASSROOM_DEMO') {
    const offset = scenarioId === 'COMBINED_CLASSROOM_DEMO' ? 6000 : 0;
    // 30 rapid TCP SYN packets to port 3000 with 0 completed 3-way handshakes, plus 10 unrelated ACK packets on port 9000
    // to prove our detector correlates flows rather than counting arbitrary ACKs!
    for (let i = 0; i < 30; i++) {
      packets.push({
        packetId: `synflood-pkt-${i}`,
        timestampMs: baseTimestampMs + offset + i * 120,
        sourceType: 'SYNTHETIC_FIXTURE',
        scenarioName: 'Synthetic Uncompleted SYN Burst Fixture',
        interfaceName: 'eth0',
        srcIp: '10.0.1.204',
        dstIp: '10.0.1.100',
        srcPort: 60000 + i,
        dstPort: 3000,
        protocol: 'TCP',
        capturedBytes: 60,
        tcpFlags: 'SYN',
        notes: 'Half-open TCP SYN without subsequent final ACK',
      });
    }
    // Add uncorrelated ACKs on an unrelated flow so tests can verify flow correlation
    for (let k = 0; k < 10; k++) {
      packets.push({
        packetId: `uncorrelated-ack-${k}`,
        timestampMs: baseTimestampMs + offset + k * 200 + 50,
        sourceType: 'SYNTHETIC_FIXTURE',
        scenarioName: 'Synthetic Uncompleted SYN Burst Fixture',
        interfaceName: 'eth0',
        srcIp: '10.0.1.55',
        dstIp: '10.0.1.100',
        srcPort: 41000,
        dstPort: 9000,
        protocol: 'TCP',
        capturedBytes: 66,
        tcpFlags: 'ACK',
        notes: 'Existing keepalive ACK on unrelated flow (not a completed SYN handshake)',
      });
    }
  }

  if (scenarioId === 'SUSPICIOUS_ARP_CONFLICT' || scenarioId === 'COMBINED_CLASSROOM_DEMO') {
    const offset = scenarioId === 'COMBINED_CLASSROOM_DEMO' ? 11000 : 0;
    packets.push(
      {
        packetId: 'arp-conflict-1',
        timestampMs: baseTimestampMs + offset + 100,
        sourceType: 'SYNTHETIC_FIXTURE',
        scenarioName: 'Synthetic ARP Conflict Fixture',
        interfaceName: 'eth0',
        srcIp: '10.0.1.1',
        dstIp: '255.255.255.255',
        srcPort: null,
        dstPort: null,
        protocol: 'ARP',
        capturedBytes: 60,
        arpOperation: 'REPLY',
        arpSenderIp: '10.0.1.1',
        arpSenderMac: '00:1A:2B:3C:4D:5E',
        notes: 'Original gateway hardware address announcement',
      },
      {
        packetId: 'arp-conflict-2',
        timestampMs: baseTimestampMs + offset + 900,
        sourceType: 'SYNTHETIC_FIXTURE',
        scenarioName: 'Synthetic ARP Conflict Fixture',
        interfaceName: 'eth0',
        srcIp: '10.0.1.1',
        dstIp: '255.255.255.255',
        srcPort: null,
        dstPort: null,
        protocol: 'ARP',
        capturedBytes: 60,
        arpOperation: 'REPLY',
        arpSenderIp: '10.0.1.1',
        arpSenderMac: 'DE:AD:BE:EF:99:01',
        notes: 'Conflicting gratuitous ARP reply claiming gateway IP 10.0.1.1',
      }
    );
  }

  if (scenarioId === 'SUSPICIOUS_DNS_TUNNELING' || scenarioId === 'COMBINED_CLASSROOM_DEMO') {
    const offset = scenarioId === 'COMBINED_CLASSROOM_DEMO' ? 13000 : 0;
    const highEntropyLabels = [
      'a8f9k2m7x4q1p9z0w3e6r5t8y2u1i0o9p4a7s2d5.telemetry-sync.example.net',
      'z9x8c7v6b5n4m3l2k1j0h9g8f7d6s5a4p3o2i1u0.telemetry-sync.example.net',
      'q1w2e3r4t5y6u7i8o9p0a9s8d7f6g5h4j3k2l1z0.telemetry-sync.example.net',
    ];
    highEntropyLabels.forEach((qname, idx) => {
      packets.push({
        packetId: `dns-susp-${idx}`,
        timestampMs: baseTimestampMs + offset + idx * 450,
        sourceType: 'SYNTHETIC_FIXTURE',
        scenarioName: 'Synthetic High-Entropy DNS Fixture',
        interfaceName: 'eth0',
        srcIp: '10.0.1.42',
        dstIp: '10.0.1.53',
        srcPort: 58200 + idx,
        dstPort: 53,
        protocol: 'DNS',
        capturedBytes: 148,
        dnsQueryName: qname,
        dnsQueryType: 'TXT',
        notes: 'Long high-entropy subdomain label in DNS TXT query',
      });
    });
  }

  return packets;
}
