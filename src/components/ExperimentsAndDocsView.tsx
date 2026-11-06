import React, { useEffect, useState } from 'react';
import {
  FIVE_MINUTE_DEMO_SCRIPT,
  REPORT_TO_IMPLEMENTATION_CHECKLIST,
  VIVA_PREPARATION_QA,
} from '../data/classroomDocs.ts';
import type { ScenarioId } from '../monitor/packetGuardEngine.ts';

export interface ExperimentLogItem {
  id: string;
  timestamp: number;
  experimentName: string;
  outcomeStatus: 'NOMINAL' | 'EXPECTED_REJECTION' | 'INFO';
  details: string;
}

interface ExperimentsAndDocsViewProps {
  experimentLogs: ExperimentLogItem[];
  onSendNormalMessage: () => Promise<void>;
  onTamperNextCiphertext: () => Promise<void>;
  onModifyNextHeader: () => Promise<void>;
  onReplayLastRecord: () => Promise<void>;
  onSendShortSequence: () => Promise<void>;
  onLoadScenario: (scenarioId: ScenarioId, clearExisting: boolean) => Promise<void>;
  onResetDemonstration: () => Promise<void>;
  onTestCrossConversationAccess: () => Promise<void>;
}

export const ExperimentsAndDocsView: React.FC<ExperimentsAndDocsViewProps> = ({
  experimentLogs,
  onSendNormalMessage,
  onTamperNextCiphertext,
  onModifyNextHeader,
  onReplayLastRecord,
  onSendShortSequence,
  onLoadScenario,
  onResetDemonstration,
  onTestCrossConversationAccess,
}) => {
  const [selectedScenario, setSelectedScenario] = useState<ScenarioId>('COMBINED_CLASSROOM_DEMO');
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [localKitFiles, setLocalKitFiles] = useState<Record<string, string>>({});
  const [selectedKitFile, setSelectedKitFile] = useState<string>('capture_worker.py');

  useEffect(() => {
    fetch('/api/local-kit/files')
      .then((r) => r.json())
      .then((data) => {
        if (data?.files) {
          setLocalKitFiles(data.files);
        }
      })
      .catch(() => {
        // Ignore offline errors
      });
  }, []);

  const runAction = async (label: string, fn: () => Promise<void>) => {
    setBusyAction(label);
    try {
      await fn();
    } finally {
      setBusyAction(null);
    }
  };

  const downloadFile = (filename: string, content: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-8">
      {/* Section 1: Interactive Security Experiments Console */}
      <div className="p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-6">
        <div className="border-b border-slate-200 dark:border-slate-800 pb-4 flex flex-col lg:flex-row lg:items-center lg:justify-between gap-2">
          <div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
              01. Interactive Classroom Security Experiments
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Every button executes real cryptographic operations on the Alice and Bob endpoints and relays real envelopes through SQLite
            </p>
          </div>
          <span className="text-xs font-mono text-slate-600 dark:text-slate-400">
            Zero simulated success results · Real AES-256-GCM &amp; Ratchet state
          </span>
        </div>

        {/* 7 Required Working Experiment Controls + Cross-Conversation Authorization Check */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 border border-slate-200 dark:border-slate-800 rounded-md flex flex-col justify-between space-y-3">
            <div className="space-y-1">
              <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                1. Normal Encrypted Delivery
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Encrypts plaintext at Alice, relays ciphertext, verifies GCM tag &amp; AAD at Bob, and advances both chains.
              </p>
            </div>
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => runAction('normal', onSendNormalMessage)}
              className="w-full px-3 py-2 text-xs font-medium bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 rounded hover:bg-slate-800 dark:hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0"
            >
              Send Normal Message
            </button>
          </div>

          <div className="p-4 border border-slate-200 dark:border-slate-800 rounded-md flex flex-col justify-between space-y-3">
            <div className="space-y-1">
              <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                2. Ciphertext Tampering (1-Bit Flip)
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Flips 1 bit in transmitted ciphertext on the relay. Bob rejects with AUTH_FAILED and preserves receive state.
              </p>
            </div>
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => runAction('tamper-cipher', onTamperNextCiphertext)}
              className="w-full px-3 py-2 text-xs font-medium bg-amber-700 text-white rounded hover:bg-amber-800 transition-colors whitespace-nowrap shrink-0"
            >
              Tamper With Next Ciphertext
            </button>
          </div>

          <div className="p-4 border border-slate-200 dark:border-slate-800 rounded-md flex flex-col justify-between space-y-3">
            <div className="space-y-1">
              <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                3. Authenticated Header Modification
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Modifies the canonical AAD record header in transit without recomputing the 128-bit GCM authentication tag.
              </p>
            </div>
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => runAction('tamper-header', onModifyNextHeader)}
              className="w-full px-3 py-2 text-xs font-medium bg-amber-700 text-white rounded hover:bg-amber-800 transition-colors whitespace-nowrap shrink-0"
            >
              Modify Next Authenticated Header
            </button>
          </div>

          <div className="p-4 border border-slate-200 dark:border-slate-800 rounded-md flex flex-col justify-between space-y-3">
            <div className="space-y-1">
              <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                4. Duplicate Record Replay
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Resends the last accepted encrypted envelope. Bob rejects with REPLAY_DETECTED (distinct from AUTH_FAILED).
              </p>
            </div>
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => runAction('replay', onReplayLastRecord)}
              className="w-full px-3 py-2 text-xs font-medium bg-red-700 text-white rounded hover:bg-red-800 transition-colors whitespace-nowrap shrink-0"
            >
              Replay Last Delivered Record
            </button>
          </div>

          <div className="p-4 border border-slate-200 dark:border-slate-800 rounded-md flex flex-col justify-between space-y-3">
            <div className="space-y-1">
              <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                5. Key Evolution &amp; Epoch Sequence
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Sends 5 identical plaintexts in sequence, proving unique message keys/nonces and triggering an Epoch transition.
              </p>
            </div>
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => runAction('sequence', onSendShortSequence)}
              className="w-full px-3 py-2 text-xs font-medium bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 rounded hover:bg-slate-800 dark:hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0"
            >
              Send Short Sequence (5 Msgs)
            </button>
          </div>

          <div className="p-4 border border-slate-200 dark:border-slate-800 rounded-md flex flex-col justify-between space-y-3">
            <div className="space-y-1">
              <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                6. Load Recorded Detection Scenario
              </div>
              <select
                value={selectedScenario}
                onChange={(e) => setSelectedScenario(e.target.value as ScenarioId)}
                className="w-full mt-1 px-2 py-1 text-xs bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded text-slate-900 dark:text-slate-100"
              >
                <option value="COMBINED_CLASSROOM_DEMO">All 4 Suspicious Fixtures</option>
                <option value="BENIGN_BASELINE_ALL">Benign Baseline (0 Alerts)</option>
                <option value="SUSPICIOUS_PORT_SCAN">Possible Port Scan</option>
                <option value="SUSPICIOUS_SYN_FLOOD">Possible SYN Flood</option>
                <option value="SUSPICIOUS_ARP_CONFLICT">Possible ARP Conflict</option>
                <option value="SUSPICIOUS_DNS_TUNNELING">Suspicious DNS Entropy</option>
              </select>
            </div>
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() =>
                runAction('scenario', () => onLoadScenario(selectedScenario, true))
              }
              className="w-full px-3 py-2 text-xs font-medium bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 rounded hover:bg-slate-800 dark:hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0"
            >
              Load Recorded Detection Scenario
            </button>
          </div>

          <div className="p-4 border border-slate-200 dark:border-slate-800 rounded-md flex flex-col justify-between space-y-3">
            <div className="space-y-1">
              <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                7. Unauthorized Cross-Conversation Test
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Attempts to read Alice–Bob envelopes as authenticated 3rd user &ldquo;mallory&rdquo;. Relay enforces HTTP 403.
              </p>
            </div>
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => runAction('mallory', onTestCrossConversationAccess)}
              className="w-full px-3 py-2 text-xs font-medium bg-slate-200 dark:bg-slate-800 text-slate-900 dark:text-slate-100 rounded hover:bg-slate-300 dark:hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
            >
              Test Mallory Access Denial (403)
            </button>
          </div>

          <div className="p-4 border border-slate-200 dark:border-slate-800 rounded-md flex flex-col justify-between space-y-3">
            <div className="space-y-1">
              <div className="text-xs font-semibold text-slate-900 dark:text-slate-100">
                8. Reset Full Demonstration
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                Generates fresh X25519 + ML-KEM-768 keys, establishes a new session ID, and resets relay &amp; packet tables.
              </p>
            </div>
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => runAction('reset', onResetDemonstration)}
              className="w-full px-3 py-2 text-xs font-medium bg-slate-200 dark:bg-slate-800 text-slate-900 dark:text-slate-100 rounded hover:bg-slate-300 dark:hover:bg-slate-700 transition-colors whitespace-nowrap shrink-0"
            >
              Reset the Demonstration
            </button>
          </div>
        </div>

        {/* Experiment Execution Audit Log */}
        <div className="border-t border-slate-200 dark:border-slate-800 pt-4">
          <div className="text-xs font-semibold text-slate-900 dark:text-slate-100 mb-2">
            Live Experiment Verification Log
          </div>
          {experimentLogs.length === 0 ? (
            <div className="text-xs text-slate-500 dark:text-slate-400 py-3">
              Click any experiment button above to observe step-by-step cryptographic and network verification output.
            </div>
          ) : (
            <div className="space-y-2 max-h-56 overflow-y-auto font-mono text-xs tabular-nums">
              {experimentLogs.map((item) => (
                <div
                  key={item.id}
                  className="p-2.5 bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-800 rounded flex flex-col md:flex-row md:items-center justify-between gap-2"
                >
                  <div>
                    <span
                      className={`font-semibold mr-2 ${
                        item.outcomeStatus === 'EXPECTED_REJECTION'
                          ? 'text-amber-700 dark:text-amber-400'
                          : item.outcomeStatus === 'NOMINAL'
                          ? 'text-emerald-700 dark:text-emerald-400'
                          : 'text-sky-700 dark:text-sky-400'
                      }`}
                    >
                      [{item.outcomeStatus}] {item.experimentName}:
                    </span>
                    <span className="text-slate-800 dark:text-slate-200 font-sans">
                      {item.details}
                    </span>
                  </div>
                  <span className="text-slate-500 shrink-0">
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Section 2: Five-Minute Classroom Presentation Script & Multi-Window Instructions */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-4">
          <div className="border-b border-slate-200 dark:border-slate-800 pb-3">
            <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              02. Five-Minute Classroom Demonstration Script
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Structured step-by-step walkthrough for live projection
            </p>
          </div>

          <div className="space-y-4">
            {FIVE_MINUTE_DEMO_SCRIPT.map((stage) => (
              <div
                key={stage.minute}
                className="p-4 border border-slate-200 dark:border-slate-800 rounded-md space-y-2"
              >
                <div className="flex items-center justify-between text-xs font-mono tabular-nums">
                  <span className="font-semibold text-slate-900 dark:text-slate-100">
                    {stage.title}
                  </span>
                  <span className="text-slate-500 dark:text-slate-400">{stage.minute}</span>
                </div>
                <ul className="space-y-1 text-xs text-slate-600 dark:text-slate-400 list-disc list-inside">
                  {stage.actions.map((act, i) => (
                    <li key={i}>{act}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>

        {/* Multi-Profile / Local Setup Guide (5 cols) */}
        <div className="lg:col-span-5 p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-4">
          <div className="border-b border-slate-200 dark:border-slate-800 pb-3">
            <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              03. Opening Isolated Alice &amp; Bob Clients + Local Setup
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Single-command startup and multi-window isolation
            </p>
          </div>

          <div className="space-y-3 text-xs text-slate-700 dark:text-slate-300">
            <div>
              <div className="font-semibold text-slate-900 dark:text-slate-100 mb-1">
                How to Open Alice &amp; Bob in Separate Windows:
              </div>
              <p className="text-slate-600 dark:text-slate-400">
                Use the Workspace Role Switcher at the top of the screen, or open two independent browser windows with URL query parameters:
              </p>
              <pre className="mt-1.5 p-2.5 bg-slate-100 dark:bg-slate-800 rounded font-mono text-[11px] overflow-x-auto">
{`Window 1 (Alice): http://localhost:3000/?role=alice
Window 2 (Bob):   http://localhost:3000/?role=bob`}
              </pre>
              <p className="mt-1 text-slate-500 dark:text-slate-400">
                Each endpoint stores its private keys and ratcheting state under its own isolated namespace and synchronizes envelopes across tabs via SQLite + BroadcastChannel.
              </p>
            </div>

            <div className="pt-2 border-t border-slate-200 dark:border-slate-800">
              <div className="font-semibold text-slate-900 dark:text-slate-100 mb-1">
                Single-Command Local Startup:
              </div>
              <pre className="p-2.5 bg-slate-100 dark:bg-slate-800 rounded font-mono text-[11px] overflow-x-auto">
{`npm install
npm run dev      # Starts full-stack server on :3000
npm test         # Runs 15 Vitest acceptance tests`}
              </pre>
            </div>

            <div className="pt-2 border-t border-slate-200 dark:border-slate-800">
              <div className="font-semibold text-slate-900 dark:text-slate-100 mb-1">
                Non-Root Live Capture Setup (Pyshark / TShark):
              </div>
              <ul className="space-y-1 text-slate-600 dark:text-slate-400 list-disc list-inside">
                <li>
                  <strong>macOS:</strong> <code className="font-mono">brew install --cask wireshark</code> (installs <code className="font-mono">ChmodBPF</code> for <code className="font-mono">lo0</code>).
                </li>
                <li>
                  <strong>Linux:</strong> <code className="font-mono">sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap</code>.
                </li>
                <li>
                  <strong>Windows:</strong> Install Wireshark with Npcap (&ldquo;Support loopback traffic&rdquo;).
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* Section 3: Viva Preparation Q&A */}
      <div className="p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-4">
        <div className="border-b border-slate-200 dark:border-slate-800 pb-3">
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            04. Viva Voce Preparation Guide
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Concise defense answers covering encryption, integrity, replay, ratcheting, epochs, metadata visibility, and heuristic detection
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {VIVA_PREPARATION_QA.map((qa) => (
            <div
              key={qa.topic}
              className="p-4 border border-slate-200 dark:border-slate-800 rounded-md space-y-2"
            >
              <div className="text-xs font-mono text-slate-500 dark:text-slate-400">
                TOPIC: {qa.topic.toUpperCase()}
              </div>
              <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">
                Q: {qa.question}
              </div>
              <p className="text-xs font-medium text-emerald-800 dark:text-emerald-400">
                Summary: {qa.conciseAnswer}
              </p>
              <p className="text-xs text-slate-600 dark:text-slate-400">{qa.technicalDetail}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Section 4: Report-to-Implementation Checklist & Documented Corrections */}
      <div className="p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-4">
        <div className="border-b border-slate-200 dark:border-slate-800 pb-3">
          <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
            05. Report-to-Implementation Verification &amp; Documented Corrections
          </h3>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Audit of implemented security requirements and corrections for common specification pitfalls
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
                <th className="py-2 px-3">Category</th>
                <th className="py-2 px-3">Requirement</th>
                <th className="py-2 px-3">Status</th>
                <th className="py-2 px-3">Implementation &amp; Engineering Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200/60 dark:divide-slate-800/70">
              {REPORT_TO_IMPLEMENTATION_CHECKLIST.map((item, idx) => (
                <tr key={idx}>
                  <td className="py-2.5 px-3 font-medium text-slate-900 dark:text-slate-100 whitespace-nowrap">
                    {item.category}
                  </td>
                  <td className="py-2.5 px-3 text-slate-700 dark:text-slate-300">
                    {item.requirement}
                  </td>
                  <td className="py-2.5 px-3 font-mono whitespace-nowrap text-emerald-700 dark:text-emerald-400 font-semibold">
                    {item.status}
                  </td>
                  <td className="py-2.5 px-3 text-slate-600 dark:text-slate-400">
                    {item.implementationNotes}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Section 5: Downloadable Local Python Flask + Pyshark Capture Worker Kit */}
      <div className="p-6 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-4">
          <div>
            <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              06. Downloadable Local Python Backend &amp; Pyshark Capture Worker
            </h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Complete standalone Python files located in <code className="font-mono">/local_python_kit/</code> for local interface packet capture
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {Object.keys(localKitFiles).map((fname) => (
              <button
                key={fname}
                type="button"
                onClick={() => setSelectedKitFile(fname)}
                className={`px-3 py-1.5 text-xs font-mono rounded transition-colors whitespace-nowrap shrink-0 ${
                  selectedKitFile === fname
                    ? 'bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900'
                    : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                }`}
              >
                {fname}
              </button>
            ))}
            {localKitFiles[selectedKitFile] && (
              <button
                type="button"
                onClick={() => downloadFile(selectedKitFile, localKitFiles[selectedKitFile])}
                className="px-3 py-1.5 text-xs font-medium bg-emerald-700 text-white rounded hover:bg-emerald-800 transition-colors whitespace-nowrap shrink-0"
              >
                Download {selectedKitFile}
              </button>
            )}
          </div>
        </div>

        <pre className="p-4 bg-slate-950 text-slate-100 rounded-md font-mono text-xs overflow-x-auto max-h-80">
          {localKitFiles[selectedKitFile] || 'Loading local Python kit file...'}
        </pre>
      </div>
    </div>
  );
};
