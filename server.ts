import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { createServer as createViteServer } from 'vite';
import { ArxRelayStore } from './src/server/relayStore.ts';
import type { ScenarioId } from './src/monitor/packetGuardEngine.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3000;
const store = new ArxRelayStore(path.join(__dirname, 'arx_packetguard.sqlite'));

// Simple per-IP sliding window rate limiter (180 req / 10s)
const rateWindows = new Map<string, number[]>();
function checkRateLimit(ip: string, maxRequests = 180, windowMs = 10000): boolean {
  const now = Date.now();
  const timestamps = (rateWindows.get(ip) || []).filter((t) => now - t < windowMs);
  if (timestamps.length >= maxRequests) {
    rateWindows.set(ip, timestamps);
    return false;
  }
  timestamps.push(now);
  rateWindows.set(ip, timestamps);
  return true;
}

async function startServer() {
  const app = express();

  // Enforce 64KB input size limit (Section 10 Web & Application Security)
  app.use(express.json({ limit: '64kb' }));

  app.use((req, res, next) => {
    const ip = req.ip || req.socket.remoteAddress || '127.0.0.1';
    if (!checkRateLimit(ip)) {
      res.status(429).json({ ok: false, error: 'Too many requests — rate limit exceeded.' });
      return;
    }
    next();
  });

  app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body || {};
    if (typeof username !== 'string' || typeof password !== 'string') {
      res.status(400).json({ ok: false, error: 'Username and password required.' });
      return;
    }
    const result = store.authenticateUser(username.trim().toLowerCase(), password);
    if (!result.ok) {
      res.status(401).json(result);
      return;
    }
    res.json(result);
  });

  app.get('/api/state', (req, res) => {
    const userHeader = String(req.headers['x-arx-user'] || 'alice');
    const actingUser = store.resolveUserFromHeader(userHeader);
    const convResult = store.getConversationEnvelopes('conv-alice-bob', actingUser);
    const captureStatus = store.probeLiveCaptureEnvironment();

    res.json({
      ok: true,
      envelopes: convResult.ok ? convResult.envelopes : [],
      accessDeniedError: convResult.ok ? null : convResult.error,
      packets: store.getPackets(),
      alerts: store.getAlerts(),
      ruleConfig: store.getRuleConfig(),
      demoSettings: store.getDemoSettings(),
      captureStatus,
      applicationEvents: store.getApplicationEvents(),
    });
  });

  app.get('/api/relay/envelopes/:conversationId', (req, res) => {
    const userHeader = String(req.headers['x-arx-user'] || '');
    const actingUser = store.resolveUserFromHeader(userHeader);
    const result = store.getConversationEnvelopes(req.params.conversationId, actingUser);
    res.status(result.status).json(result);
  });

  app.post('/api/relay/handshake', (req, res) => {
    const userHeader = String(req.headers['x-arx-user'] || 'alice');
    const actingUser = store.resolveUserFromHeader(userHeader);
    const { conversationId = 'conv-alice-bob', handshake } = req.body || {};
    if (!handshake || typeof handshake.sessionId !== 'string') {
      res.status(400).json({ ok: false, error: 'Valid handshake object required.' });
      return;
    }
    const result = store.storeHandshake(conversationId, actingUser, handshake);
    res.status(result.status).json(result);
  });

  app.post('/api/relay/send', (req, res) => {
    const userHeader = String(req.headers['x-arx-user'] || 'alice');
    const actingUser = store.resolveUserFromHeader(userHeader);
    const { conversationId = 'conv-alice-bob', envelope } = req.body || {};
    if (!envelope || !envelope.header || typeof envelope.ciphertextHex !== 'string') {
      res.status(400).json({ ok: false, error: 'Malformed encrypted envelope.' });
      return;
    }
    const result = store.relayEnvelope(conversationId, actingUser, envelope);
    res.status(result.status).json(result);
  });

  app.post('/api/relay/delivery-status', (req, res) => {
    const { envelopeId, deliveryStatus } = req.body || {};
    if (
      typeof envelopeId === 'string' &&
      ['DELIVERED_VERIFIED', 'REJECTED_AUTH_FAILED', 'REJECTED_REPLAY'].includes(deliveryStatus)
    ) {
      store.updateEnvelopeDeliveryStatus(envelopeId, deliveryStatus);
      res.json({ ok: true });
      return;
    }
    res.status(400).json({ ok: false, error: 'Invalid delivery status update.' });
  });

  app.post('/api/demo/settings', (req, res) => {
    const updated = store.updateDemoSettings(req.body || {});
    res.json({ ok: true, demoSettings: updated });
  });

  app.post('/api/monitor/scenario', (req, res) => {
    const { scenarioId = 'BENIGN_BASELINE_ALL', clearExisting = true } = req.body || {};
    const validScenarios: ScenarioId[] = [
      'BENIGN_BASELINE_ALL',
      'SUSPICIOUS_PORT_SCAN',
      'SUSPICIOUS_SYN_FLOOD',
      'SUSPICIOUS_ARP_CONFLICT',
      'SUSPICIOUS_DNS_TUNNELING',
      'COMBINED_CLASSROOM_DEMO',
    ];
    if (!validScenarios.includes(scenarioId)) {
      res.status(400).json({ ok: false, error: 'Unknown scenarioId.' });
      return;
    }
    const data = store.loadScenarioPackets(scenarioId, Boolean(clearExisting));
    res.json({ ok: true, ...data });
  });

  app.post('/api/monitor/rules', (req, res) => {
    const updated = store.updateRuleConfig(req.body || {});
    res.json({ ok: true, ...updated });
  });

  app.post('/api/monitor/ingest-packets', (req, res) => {
    const { packets } = req.body || {};
    if (!Array.isArray(packets)) {
      res.status(400).json({ ok: false, error: 'packets array required.' });
      return;
    }
    store.insertPackets(packets);
    res.json({
      ok: true,
      ingestedCount: packets.length,
      alerts: store.getAlerts(),
    });
  });

  app.post('/api/demo/reset', (_req, res) => {
    store.resetAll();
    res.json({
      ok: true,
      envelopes: [],
      packets: store.getPackets(),
      alerts: store.getAlerts(),
      demoSettings: store.getDemoSettings(),
    });
  });

  app.get('/api/local-kit/files', (_req, res) => {
    const kitDir = path.join(__dirname, 'local_python_kit');
    const filenames = ['app.py', 'capture_worker.py', 'requirements.txt', 'start_local.sh'];
    const files: Record<string, string> = {};
    for (const fname of filenames) {
      const fullPath = path.join(kitDir, fname);
      if (fs.existsSync(fullPath)) {
        files[fname] = fs.readFileSync(fullPath, 'utf8');
      }
    }
    res.json({ ok: true, files });
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`==================================================================`);
    console.log(`  ARX-PacketGuard Server listening on http://localhost:${PORT}`);
    console.log(`  - Classroom Workspace:  http://localhost:${PORT}`);
    console.log(`  - Alice Endpoint View:  http://localhost:${PORT}/?role=alice`);
    console.log(`  - Bob Endpoint View:    http://localhost:${PORT}/?role=bob`);
    console.log(`==================================================================`);
  });
}

startServer();
