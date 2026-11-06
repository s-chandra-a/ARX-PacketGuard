import React, { useMemo, useState } from 'react';
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import {
  computeTrafficMetrics,
  type DetectionRuleConfig,
  type HeuristicAlert,
  type PacketMetadataRecord,
  type PacketProtocol,
  type ScenarioId,
} from '../monitor/packetGuardEngine.ts';
import type { LiveCaptureStatus } from '../server/relayStore.ts';

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: '#3b82f6',
  HTTP: '#10b981',
  DNS: '#8b5cf6',
  ARP: '#f59e0b',
  UDP: '#06b6d4',
  TLS: '#ec4899',
};

interface PacketDashboardViewProps {
  packets: PacketMetadataRecord[];
  alerts: HeuristicAlert[];
  ruleConfig: DetectionRuleConfig;
  captureStatus: LiveCaptureStatus | null;
  perspective: 'alice' | 'bob' | 'relay';
  onChangePerspective: (p: 'alice' | 'bob' | 'relay') => void;
  onLoadScenario: (scenarioId: ScenarioId, clearExisting: boolean) => Promise<void>;
  onUpdateRules: (newConfig: Partial<DetectionRuleConfig>) => Promise<void>;
}

export const PacketDashboardView: React.FC<PacketDashboardViewProps> = ({
  packets,
  alerts,
  ruleConfig,
  captureStatus,
  perspective,
  onChangePerspective,
  onLoadScenario,
  onUpdateRules,
}) => {
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [endpointFilter, setEndpointFilter] = useState<string>('');
  const [portFilter, setPortFilter] = useState<string>('');
  const [timeWindowSec, setTimeWindowSec] = useState<string>('ALL');

  // Local editable rule config state
  const [draftRules, setDraftRules] = useState<DetectionRuleConfig>(ruleConfig);
  const [isApplyingRules, setIsApplyingRules] = useState(false);

  React.useEffect(() => {
    setDraftRules(ruleConfig);
  }, [ruleConfig]);

  const filteredPackets = useMemo(() => {
    let list = [...packets];
    if (protocolFilter !== 'ALL') {
      list = list.filter((p) => p.protocol === protocolFilter);
    }
    if (endpointFilter.trim()) {
      const q = endpointFilter.trim().toLowerCase();
      list = list.filter(
        (p) =>
          p.srcIp.toLowerCase().includes(q) ||
          p.dstIp.toLowerCase().includes(q) ||
          (p.dnsQueryName && p.dnsQueryName.toLowerCase().includes(q)) ||
          (p.arpSenderMac && p.arpSenderMac.toLowerCase().includes(q))
      );
    }
    if (portFilter.trim()) {
      const portNum = Number(portFilter.trim());
      if (!Number.isNaN(portNum)) {
        list = list.filter((p) => p.srcPort === portNum || p.dstPort === portNum);
      }
    }
    if (timeWindowSec !== 'ALL' && list.length > 0) {
      const maxTs = Math.max(...list.map((p) => p.timestampMs));
      const cutoff = maxTs - Number(timeWindowSec) * 1000;
      list = list.filter((p) => p.timestampMs >= cutoff);
    }
    return list;
  }, [packets, protocolFilter, endpointFilter, portFilter, timeWindowSec]);

  const metrics = useMemo(
    () => computeTrafficMetrics(filteredPackets, perspective),
    [filteredPackets, perspective]
  );

  const activeDataSources = useMemo(() => {
    const sources = new Set(packets.map((p) => p.sourceType));
    return Array.from(sources);
  }, [packets]);

  const handleApplyRules = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsApplyingRules(true);
    try {
      await onUpdateRules(draftRules);
    } finally {
      setIsApplyingRules(false);
    }
  };

  const maxBucketBytes = Math.max(
    1,
    ...metrics.timeSeriesBuckets.map((b) => Math.max(b.incomingBytes, b.outgoingBytes))
  );
  const maxBucketPps = Math.max(1, ...metrics.timeSeriesBuckets.map((b) => b.pps));

  return (
    <div className="space-y-8">
      {/* Data Source & Capture Architecture Header */}
      <div className="p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-600 dark:text-slate-400">
              <span className="font-semibold text-slate-900 dark:text-slate-100">
                DATA SOURCE CLASSIFICATION:
              </span>
              {activeDataSources.length === 0 ? (
                <span>NO PACKETS LOADED</span>
              ) : (
                activeDataSources.map((src, i) => (
                  <React.Fragment key={src}>
                    {i > 0 && <span aria-hidden="true">·</span>}
                    <span className="font-semibold text-amber-700 dark:text-amber-400">
                      {src === 'RECORDED_PCAP_TRACE'
                        ? 'RECORDED CAPTURE (PCAP TRACE)'
                        : src === 'SYNTHETIC_FIXTURE'
                        ? 'SYNTHETIC FIXTURE (CLASSROOM HEURISTIC TEST)'
                        : 'LIVE CAPTURE WORKER (TSHARK)'}
                    </span>
                  </React.Fragment>
                ))
              )}
              <span aria-hidden="true">·</span>
              <span>Interface: {captureStatus?.selectedInterface || 'lo0'}</span>
            </div>
            <p className="text-xs text-slate-600 dark:text-slate-400">
              {captureStatus?.fallbackReason ||
                'PacketGuard inspects network metadata (IPs, ports, byte lengths, TCP flags, ARP/DNS headers) independently without access to ARX keys.'}
            </p>
          </div>

          {/* Preset Fixture Loader Controls */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => onLoadScenario('BENIGN_BASELINE_ALL', true)}
              className="px-3 py-1.5 text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              Load Benign Baseline
            </button>
            <button
              type="button"
              onClick={() => onLoadScenario('SUSPICIOUS_PORT_SCAN', false)}
              className="px-3 py-1.5 text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              + Port Scan Fixture
            </button>
            <button
              type="button"
              onClick={() => onLoadScenario('SUSPICIOUS_SYN_FLOOD', false)}
              className="px-3 py-1.5 text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              + SYN Flood Fixture
            </button>
            <button
              type="button"
              onClick={() => onLoadScenario('SUSPICIOUS_ARP_CONFLICT', false)}
              className="px-3 py-1.5 text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              + ARP Conflict Fixture
            </button>
            <button
              type="button"
              onClick={() => onLoadScenario('SUSPICIOUS_DNS_TUNNELING', false)}
              className="px-3 py-1.5 text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-800 dark:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              + DNS Entropy Fixture
            </button>
            <button
              type="button"
              onClick={() => onLoadScenario('COMBINED_CLASSROOM_DEMO', true)}
              className="px-3 py-1.5 text-xs font-medium bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 hover:bg-slate-800 dark:hover:bg-slate-200 rounded-md transition-colors whitespace-nowrap shrink-0"
            >
              Load All 4 Heuristic Scenarios
            </button>
          </div>
        </div>
      </div>

      {/* Perspective Selector & Summary Metric Strip */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg flex flex-col justify-between">
          <div className="text-xs text-slate-500 dark:text-slate-400">
            Direction Perspective (Loopback Port Convention)
          </div>
          <div className="mt-2 flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800 rounded-md">
            {(['alice', 'bob', 'relay'] as const).map((role) => (
              <button
                key={role}
                type="button"
                onClick={() => onChangePerspective(role)}
                className={`flex-1 px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                  perspective === role
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                {role === 'alice'
                  ? 'Alice (:54110)'
                  : role === 'bob'
                  ? 'Bob (:54120)'
                  : 'Relay (:3000)'}
              </button>
            ))}
          </div>
          <div className="mt-2 text-[11px] text-slate-500 dark:text-slate-400">
            Outgoing = sent from selected port/IP · Incoming = received by selected port/IP
          </div>
        </div>

        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg">
          <div className="text-xs text-slate-500 dark:text-slate-400">
            Captured Network Volume ({perspective.toUpperCase()})
          </div>
          <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
            {metrics.totalCapturedBytes.toLocaleString()} B
          </div>
          <div className="mt-1 text-xs font-mono tabular-nums text-slate-600 dark:text-slate-400">
            Out: {metrics.outgoingBytesClient.toLocaleString()} B · In:{' '}
            {metrics.incomingBytesClient.toLocaleString()} B
          </div>
        </div>

        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg">
          <div className="text-xs text-slate-500 dark:text-slate-400">
            Packet &amp; Byte Throughput
          </div>
          <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
            {metrics.packetsPerSecond} pkt/s
          </div>
          <div className="mt-1 text-xs font-mono tabular-nums text-slate-600 dark:text-slate-400">
            {metrics.bytesPerSecond.toLocaleString()} B/s · {metrics.totalPackets} total packets
          </div>
        </div>

        <div className="p-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg">
          <div className="text-xs text-slate-500 dark:text-slate-400">
            Heuristic Anomaly Alerts
          </div>
          <div className="mt-1 text-2xl font-semibold font-mono tabular-nums text-slate-900 dark:text-slate-100">
            {alerts.length} {alerts.length === 1 ? 'Alert' : 'Alerts'}
          </div>
          <div className="mt-1 text-xs text-slate-600 dark:text-slate-400">
            {alerts.length === 0
              ? 'STATUS: NOMINAL (No heuristic thresholds exceeded)'
              : `STATUS: REVIEW REQUIRED (${alerts.length} suspicious metadata patterns)`}
          </div>
        </div>
      </div>

      {/* Charts Grid: Incoming/Outgoing Byte Rate, Packets Per Second, and Protocol Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Chart 1: Incoming vs Outgoing Bytes per Bucket */}
        <div className="p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                01. Incoming vs. Outgoing Bytes
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Relative to {perspective.toUpperCase()} endpoint across capture window
              </p>
            </div>
            <div className="text-xs font-mono text-slate-500 dark:text-slate-400">
              Blue: Out · Emerald: In
            </div>
          </div>

          {metrics.timeSeriesBuckets.length === 0 ? (
            <div className="h-44 flex items-center justify-center text-xs text-slate-500">
              No packets matching current filter.
            </div>
          ) : (
            <div className="h-44 flex items-end gap-2 pt-4 pb-6 border-b border-slate-200 dark:border-slate-800 relative">
              {metrics.timeSeriesBuckets.map((b) => {
                const outHeight = Math.max(4, Math.round((b.outgoingBytes / maxBucketBytes) * 110));
                const inHeight = Math.max(4, Math.round((b.incomingBytes / maxBucketBytes) * 110));
                return (
                  <div
                    key={b.bucketTimestampMs}
                    className="flex-1 flex flex-col items-center gap-1 group relative"
                  >
                    <div className="w-full flex items-end justify-center gap-0.5 h-28">
                      <div
                        style={{ height: `${outHeight}px` }}
                        className="w-2.5 bg-sky-600 dark:bg-sky-500 rounded-t transition-opacity group-hover:opacity-80"
                        title={`Outgoing: ${b.outgoingBytes} B`}
                      />
                      <div
                        style={{ height: `${inHeight}px` }}
                        className="w-2.5 bg-emerald-600 dark:bg-emerald-500 rounded-t transition-opacity group-hover:opacity-80"
                        title={`Incoming: ${b.incomingBytes} B`}
                      />
                    </div>
                    <span className="text-[10px] font-mono tabular-nums text-slate-500 dark:text-slate-400">
                      {b.label}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Chart 2: Packets Per Second (PPS) */}
        <div className="p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                02. Packets Per Second (PPS)
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Capture timestamp rate distribution
              </p>
            </div>
            <span className="text-xs font-mono tabular-nums text-slate-600 dark:text-slate-400">
              Peak: {maxBucketPps} pkt/s
            </span>
          </div>

          {metrics.timeSeriesBuckets.length === 0 ? (
            <div className="h-44 flex items-center justify-center text-xs text-slate-500">
              No packets matching current filter.
            </div>
          ) : (
            <div className="h-44 flex items-end gap-2 pt-4 pb-6 border-b border-slate-200 dark:border-slate-800">
              {metrics.timeSeriesBuckets.map((b) => {
                const barHeight = Math.max(4, Math.round((b.pps / maxBucketPps) * 110));
                return (
                  <div
                    key={b.bucketTimestampMs}
                    className="flex-1 flex flex-col items-center gap-1"
                  >
                    <div className="w-full flex items-end justify-center h-28">
                      <div
                        style={{ height: `${barHeight}px` }}
                        className="w-4 bg-slate-700 dark:bg-slate-300 rounded-t"
                        title={`${b.pps} pkt/s (${b.packetCount} pkts)`}
                      />
                    </div>
                    <span className="text-[10px] font-mono tabular-nums text-slate-500 dark:text-slate-400">
                      {b.label}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Chart 3: Protocol Distribution (Recharts Pie Chart) */}
        <div className="p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              03. Protocol Distribution
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Observed layer classification across {metrics.totalPackets} packets
            </p>
          </div>

          {metrics.totalPackets === 0 ? (
            <div className="h-44 flex items-center justify-center text-xs text-slate-500">
              No packets matching current filter.
            </div>
          ) : (
            <div className="h-48 w-full my-2">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={Object.entries(metrics.protocolBreakdown)
                      .filter(([_, count]) => count > 0)
                      .map(([name, value]) => ({ name, value }))}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={75}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {Object.entries(metrics.protocolBreakdown)
                      .filter(([_, count]) => count > 0)
                      .map(([name]) => (
                        <Cell
                          key={`cell-${name}`}
                          fill={PROTOCOL_COLORS[name] || '#64748b'}
                        />
                      ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#1e293b',
                      borderRadius: '0.375rem',
                      color: '#f8fafc',
                      fontSize: '12px',
                    }}
                    formatter={(value: any) => [`${value} packets`, 'Volume']}
                  />
                  <Legend
                    formatter={(value) => <span className="text-xs font-mono text-slate-700 dark:text-slate-300">{value}</span>}
                    layout="horizontal"
                    verticalAlign="bottom"
                    align="center"
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}

          <div className="text-[11px] font-mono text-slate-500 text-center">
            Interactive Recharts proportion breakdown
          </div>
        </div>
      </div>

      {/* Configurable Heuristic Rule Thresholds + Active Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Configurable Thresholds Form (5 cols) */}
        <form
          onSubmit={handleApplyRules}
          className="lg:col-span-5 p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-4"
        >
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                Heuristic Rule Engine Thresholds
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Adjust parameters and re-evaluate metadata stream
              </p>
            </div>
            <button
              type="submit"
              disabled={isApplyingRules}
              className="px-3 py-1.5 text-xs font-medium bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 rounded-md hover:bg-slate-800 dark:hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0"
            >
              {isApplyingRules ? 'Applying...' : 'Apply & Re-evaluate'}
            </button>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <label className="space-y-1">
              <span className="text-slate-600 dark:text-slate-400 block">
                Port Scan: Distinct Ports
              </span>
              <input
                type="number"
                min={2}
                max={200}
                value={draftRules.portScanDistinctPortsThreshold}
                onChange={(e) =>
                  setDraftRules({
                    ...draftRules,
                    portScanDistinctPortsThreshold: Number(e.target.value),
                  })
                }
                className="w-full px-2.5 py-1.5 font-mono tabular-nums bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded text-slate-900 dark:text-slate-100"
              />
            </label>

            <label className="space-y-1">
              <span className="text-slate-600 dark:text-slate-400 block">
                Port Scan: Window (sec)
              </span>
              <input
                type="number"
                min={1}
                max={120}
                value={draftRules.portScanWindowSeconds}
                onChange={(e) =>
                  setDraftRules({
                    ...draftRules,
                    portScanWindowSeconds: Number(e.target.value),
                  })
                }
                className="w-full px-2.5 py-1.5 font-mono tabular-nums bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded text-slate-900 dark:text-slate-100"
              />
            </label>

            <label className="space-y-1">
              <span className="text-slate-600 dark:text-slate-400 block">
                SYN Flood: Min SYN Count
              </span>
              <input
                type="number"
                min={3}
                max={500}
                value={draftRules.synFloodCountThreshold}
                onChange={(e) =>
                  setDraftRules({
                    ...draftRules,
                    synFloodCountThreshold: Number(e.target.value),
                  })
                }
                className="w-full px-2.5 py-1.5 font-mono tabular-nums bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded text-slate-900 dark:text-slate-100"
              />
            </label>

            <label className="space-y-1">
              <span className="text-slate-600 dark:text-slate-400 block">
                SYN Max Completion Ratio (0–1)
              </span>
              <input
                type="number"
                step="0.05"
                min={0}
                max={1}
                value={draftRules.synFloodMaxCompletionRatio}
                onChange={(e) =>
                  setDraftRules({
                    ...draftRules,
                    synFloodMaxCompletionRatio: Number(e.target.value),
                  })
                }
                className="w-full px-2.5 py-1.5 font-mono tabular-nums bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded text-slate-900 dark:text-slate-100"
              />
            </label>

            <label className="space-y-1">
              <span className="text-slate-600 dark:text-slate-400 block">
                ARP Conflict: Distinct MACs
              </span>
              <input
                type="number"
                min={2}
                max={10}
                value={draftRules.arpDistinctMacThreshold}
                onChange={(e) =>
                  setDraftRules({
                    ...draftRules,
                    arpDistinctMacThreshold: Number(e.target.value),
                  })
                }
                className="w-full px-2.5 py-1.5 font-mono tabular-nums bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded text-slate-900 dark:text-slate-100"
              />
            </label>

            <label className="space-y-1">
              <span className="text-slate-600 dark:text-slate-400 block">
                DNS Max Label Entropy (bits)
              </span>
              <input
                type="number"
                step="0.1"
                min={2.0}
                max={5.0}
                value={draftRules.dnsMaxLabelEntropy}
                onChange={(e) =>
                  setDraftRules({
                    ...draftRules,
                    dnsMaxLabelEntropy: Number(e.target.value),
                  })
                }
                className="w-full px-2.5 py-1.5 font-mono tabular-nums bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded text-slate-900 dark:text-slate-100"
              />
            </label>

            <label className="space-y-1">
              <span className="text-slate-600 dark:text-slate-400 block">
                DNS Max Label Length (chars)
              </span>
              <input
                type="number"
                min={10}
                max={120}
                value={draftRules.dnsMaxLabelLength}
                onChange={(e) =>
                  setDraftRules({
                    ...draftRules,
                    dnsMaxLabelLength: Number(e.target.value),
                  })
                }
                className="w-full px-2.5 py-1.5 font-mono tabular-nums bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded text-slate-900 dark:text-slate-100"
              />
            </label>

            <label className="space-y-1">
              <span className="text-slate-600 dark:text-slate-400 block">
                Duplicate Alert Cooldown (sec)
              </span>
              <input
                type="number"
                min={1}
                max={300}
                value={draftRules.alertCooldownSeconds}
                onChange={(e) =>
                  setDraftRules({
                    ...draftRules,
                    alertCooldownSeconds: Number(e.target.value),
                  })
                }
                className="w-full px-2.5 py-1.5 font-mono tabular-nums bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded text-slate-900 dark:text-slate-100"
              />
            </label>
          </div>
        </form>

        {/* Heuristic Alerts Evidence Panel (7 cols) */}
        <div className="lg:col-span-7 p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-4">
          <div className="border-b border-slate-200 dark:border-slate-800 pb-3 flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                Heuristic Detection Alerts &amp; Evidence
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Metadata heuristics highlight suspicious patterns; they are not cryptographic proof of attack
              </p>
            </div>
            <span className="text-xs font-mono tabular-nums text-slate-600 dark:text-slate-400">
              {alerts.length} active
            </span>
          </div>

          {alerts.length === 0 ? (
            <div className="py-10 text-center space-y-2">
              <div className="text-sm font-medium text-emerald-700 dark:text-emerald-400">
                NOMINAL TRAFFIC STATE — Zero Heuristic Alerts Triggered
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md mx-auto">
                All observed flows satisfy current port-count, 3-way TCP handshake completion, ARP consistency, and DNS entropy thresholds. Click &ldquo;Load All 4 Heuristic Scenarios&rdquo; above to test anomaly detection.
              </p>
            </div>
          ) : (
            <div className="space-y-3 max-h-96 overflow-y-auto pr-1">
              {alerts.map((alert) => (
                <div
                  key={alert.alertId}
                  className="p-4 border border-slate-200 dark:border-slate-800 rounded-md bg-slate-50/60 dark:bg-slate-800/40 space-y-2"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono tabular-nums">
                    <span className="font-semibold text-amber-700 dark:text-amber-400">
                      [{alert.severity}: {alert.ruleId}] {alert.title}
                    </span>
                    <span className="text-slate-500 dark:text-slate-400">
                      Source: {alert.sourceType} · {new Date(alert.timestampMs).toLocaleTimeString()}
                    </span>
                  </div>

                  <p className="text-xs text-slate-800 dark:text-slate-200">
                    {alert.evidenceSummary}
                  </p>

                  <div className="text-xs font-mono tabular-nums text-slate-600 dark:text-slate-400 flex flex-wrap items-center gap-2">
                    <span>Observed: {alert.observedValue}</span>
                    <span aria-hidden="true">·</span>
                    <span>Threshold: {alert.thresholdValue}</span>
                    <span aria-hidden="true">·</span>
                    <span>
                      Endpoints: {alert.srcIp} → {alert.dstIp}
                    </span>
                  </div>

                  <div className="text-xs text-slate-600 dark:text-slate-400 pt-1 border-t border-slate-200/70 dark:border-slate-700/60">
                    <strong className="font-medium text-slate-700 dark:text-slate-300">
                      Benign Cause Note:
                    </strong>{' '}
                    {alert.benignExplanation}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Filterable Packet Metadata Table */}
      <div className="p-5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
              Captured &amp; Replayed Packet Metadata Table
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Showing {filteredPackets.length} of {packets.length} packets · Zero message plaintext is ever accessible in packet captures during encrypted mode
            </p>
          </div>

          {/* Filter Controls */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1 p-1 bg-slate-100 dark:bg-slate-800 rounded-md">
              {['ALL', 'TCP', 'HTTP', 'DNS', 'ARP', 'UDP'].map((proto) => (
                <button
                  key={proto}
                  type="button"
                  onClick={() => setProtocolFilter(proto)}
                  className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap shrink-0 ${
                    protocolFilter === proto
                      ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-slate-100 shadow-xs'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900'
                  }`}
                >
                  {proto}
                </button>
              ))}
            </div>

            <input
              type="text"
              placeholder="Filter IP / DNS / MAC..."
              value={endpointFilter}
              onChange={(e) => setEndpointFilter(e.target.value)}
              className="px-2.5 py-1.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded text-slate-900 dark:text-slate-100"
            />

            <input
              type="text"
              placeholder="Port (e.g. 3000)"
              value={portFilter}
              onChange={(e) => setPortFilter(e.target.value)}
              className="w-28 px-2.5 py-1.5 text-xs font-mono bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded text-slate-900 dark:text-slate-100"
            />

            <select
              value={timeWindowSec}
              onChange={(e) => setTimeWindowSec(e.target.value)}
              className="px-2.5 py-1.5 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded text-slate-900 dark:text-slate-100"
            >
              <option value="ALL">All Time</option>
              <option value="5">Last 5s of trace</option>
              <option value="10">Last 10s of trace</option>
              <option value="30">Last 30s of trace</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto max-h-96">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400 font-medium">
                <th className="py-2 px-3">Timestamp</th>
                <th className="py-2 px-3">Data Source</th>
                <th className="py-2 px-3">Source IP:Port</th>
                <th className="py-2 px-3">Destination IP:Port</th>
                <th className="py-2 px-3">Protocol</th>
                <th className="py-2 px-3 text-right">Size (B)</th>
                <th className="py-2 px-3">TCP Flags / ARP / DNS Metadata</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/70 font-mono tabular-nums">
              {filteredPackets.slice(0, 120).map((pkt) => (
                <tr
                  key={pkt.packetId}
                  className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
                >
                  <td className="py-2 px-3 whitespace-nowrap text-slate-600 dark:text-slate-400">
                    {new Date(pkt.timestampMs).toISOString().slice(11, 23)}
                  </td>
                  <td className="py-2 px-3 whitespace-nowrap text-slate-700 dark:text-slate-300">
                    {pkt.sourceType === 'RECORDED_PCAP_TRACE'
                      ? 'RECORDED_PCAP'
                      : pkt.sourceType === 'SYNTHETIC_FIXTURE'
                      ? 'SYNTHETIC_FIXTURE'
                      : 'LIVE_TSHARK'}
                  </td>
                  <td className="py-2 px-3 whitespace-nowrap text-slate-900 dark:text-slate-100">
                    {pkt.srcIp}
                    {pkt.srcPort !== null ? `:${pkt.srcPort}` : ''}
                  </td>
                  <td className="py-2 px-3 whitespace-nowrap text-slate-900 dark:text-slate-100">
                    {pkt.dstIp}
                    {pkt.dstPort !== null ? `:${pkt.dstPort}` : ''}
                  </td>
                  <td className="py-2 px-3 whitespace-nowrap font-semibold text-slate-800 dark:text-slate-200">
                    {pkt.protocol}
                  </td>
                  <td className="py-2 px-3 text-right whitespace-nowrap text-slate-900 dark:text-slate-100">
                    {pkt.capturedBytes}
                  </td>
                  <td className="py-2 px-3 font-sans text-slate-600 dark:text-slate-400">
                    {pkt.tcpFlags && (
                      <span className="font-mono text-slate-800 dark:text-slate-200 mr-2">
                        Flags: [{pkt.tcpFlags}]
                      </span>
                    )}
                    {pkt.arpSenderMac && (
                      <span className="font-mono text-amber-700 dark:text-amber-400 mr-2">
                        ARP {pkt.arpSenderIp} is-at {pkt.arpSenderMac}
                      </span>
                    )}
                    {pkt.dnsQueryName && (
                      <span className="font-mono text-sky-700 dark:text-sky-400 mr-2">
                        DNS {pkt.dnsQueryType || 'A'}? {pkt.dnsQueryName}
                      </span>
                    )}
                    {pkt.notes && <span>{pkt.notes}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
