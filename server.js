import 'dotenv/config'; // IMPORTANT: .env încărcat la start
import express from 'express';
import http from 'http';
import cors from 'cors';
import { WebSocketServer } from 'ws';
import { Client as SSHClient } from 'ssh2';
import fs from 'fs/promises';
import fssync from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

import passport from 'passport';
import authRoutes, { requireAuth } from './auth.js';

// --- căi & utilitare ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.cwd(), process.env.DATA_DIR) : __dirname;
const SERVERS_PATH = path.join(DATA_DIR, 'servers.json');

async function ensureDataFile() {
  if (!fssync.existsSync(DATA_DIR)) fssync.mkdirSync(DATA_DIR, { recursive: true });
  if (!fssync.existsSync(SERVERS_PATH)) fssync.writeFileSync(SERVERS_PATH, '[]', 'utf8');
}

async function readServers() {
  await ensureDataFile();
  const raw = (await fs.readFile(SERVERS_PATH, 'utf8')).trim();
  if (!raw) return [];
  try { return JSON.parse(raw); } catch { return []; }
}
async function writeServersAtomic(list) {
  await ensureDataFile();
  const tmp = SERVERS_PATH + '.tmp';
  await fs.writeFile(tmp, JSON.stringify(list, null, 2), 'utf8');
  await fs.rename(tmp, SERVERS_PATH);
}

// validare minimă
function validateServerPayload(body, { partial = false } = {}) {
  const required = ['name', 'host', 'username'];
  if (!partial) {
    for (const k of required) if (!body?.[k]) throw new Error(`Câmp lipsă: ${k}`);
  }
  if (body?.port != null) {
    const p = Number(body.port);
    if (!Number.isInteger(p) || p < 1 || p > 65535) throw new Error('Port invalid');
  }
}

// --- config restricții host (opțional) ---
const ALLOWED = (process.env.ALLOWED_SSH_HOSTS || '')
  .split(',').map(s => s.trim()).filter(Boolean);
function assertAllowedHost(host) {
  if (!ALLOWED.length) return;
  if (!ALLOWED.includes(host)) throw new Error(`Host ${host} nu este permis`);
}

// --- app/websocket ---
const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',') || true, credentials: true }));

// init passport + rute auth (acum că avem app)
app.use(passport.initialize());
app.use('/api/auth', authRoutes);

const httpServer = http.createServer(app);
const wss = new WebSocketServer({ server: httpServer, path: '/ws/ssh' });

// ---------- API REST: CRUD pe servers.json (protejate cu JWT) ----------
app.get('/api/servers', requireAuth, async (req, res) => {
  const list = await readServers();
  res.json(list);
});

app.post('/api/servers', requireAuth, async (req, res) => {
  try {
    validateServerPayload(req.body);
    const list = await readServers();
    const id = Math.random().toString(36).slice(2, 10);
    const server = {
      id,
      name: req.body.name,
      host: req.body.host,
      port: req.body.port ?? 22,
      username: req.body.username,
      tags: Array.isArray(req.body.tags) ? req.body.tags : undefined,
      note: req.body.note ?? undefined,
    };
    if (list.some(s => s.host === server.host && s.username === server.username && (s.port ?? 22) === (server.port ?? 22))) {
      return res.status(409).json({ error: 'Server deja există (host+username+port)' });
    }
    await writeServersAtomic([...list, server]);
    res.status(201).json(server);
  } catch (e) {
    res.status(400).json({ error: e.message || 'Payload invalid' });
  }
});

app.put('/api/servers/:id', requireAuth, async (req, res) => {
  try {
    validateServerPayload(req.body, { partial: true });
    const list = await readServers();
    const idx = list.findIndex(s => s.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Server inexistent' });
    const merged = { ...list[idx], ...req.body };
    if (list.some(s =>
      s.id !== merged.id &&
      s.host === merged.host &&
      s.username === merged.username &&
      (s.port ?? 22) === (merged.port ?? 22)
    )) {
      return res.status(409).json({ error: 'Combinatie host+username+port deja folosită' });
    }
    list[idx] = merged;
    await writeServersAtomic(list);
    res.json(merged);
  } catch (e) {
    res.status(400).json({ error: e.message || 'Payload invalid' });
  }
});

app.delete('/api/servers/:id', requireAuth, async (req, res) => {
  const list = await readServers();
  const idx = list.findIndex(s => s.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Server inexistent' });
  const [removed] = list.splice(idx, 1);
  await writeServersAtomic(list);
  res.json(removed);
});

// ---------- WebSocket SSH (opțional protejat cu JWT) ----------
const USE_AUTH = process.env.USE_AUTH !== 'false';

wss.on('connection', (ws) => {
  let ssh, stream;
  let alive = true;

  ws.on('message', async (raw) => {
    if (!ssh) {
      // Primul mesaj: { serverId, cols, rows, auth: { password | privateKey }, token? }
      let cfg;
      try { cfg = JSON.parse(raw.toString()); }
      catch { ws.close(1008, 'Primul mesaj trebuie să fie JSON'); return; }

      if (USE_AUTH) {
        try {
          const t = cfg.token;
          if (!t) throw new Error('Missing JWT');
          // simplu: verificăm cu secretn
          const payload = await import('jsonwebtoken').then(m => m.default.verify(t, process.env.JWT_SECRET));
          // (payload disponibil dacă vrei să-l folosești)
        } catch (e) {
          ws.close(1008, 'JWT invalid');
          return;
        }
      }

      const servers = await readServers();
      const srv = servers.find(s => s.id === cfg.serverId);
      if (!srv) { ws.close(1008, 'Server necunoscut'); return; }
      try { assertAllowedHost(srv.host); } catch (e) { ws.close(1008, e.message); return; }

      ssh = new SSHClient();
      ssh
        .on('keyboard-interactive', (name, instructions, lang, prompts, finish) => {
          const answers = prompts.map(() => cfg.auth?.password || '');
          finish(answers);
        })
        .on('ready', () => {
          console.log('[SSH] ready', srv.host, srv.port);
          ssh.shell({ term: 'xterm-256color', cols: cfg.cols || 80, rows: cfg.rows || 24 }, (err, s) => {
            if (err) { ws.close(1011, `PTY error: ${err.message}`); return; }
            stream = s;
            stream.on('data', d => alive && ws.send(d));
            stream.stderr?.on('data', d => alive && ws.send(d));
            stream.on('close', () => { try { ws.close(); } catch {} });
          });
        })
        .on('error', (e) => {
          console.error('[SSH ERROR]', e.message);
          try { ws.send(Buffer.from(`\r\n[SSH ERROR] ${e.message}\r\n`)); } catch {}
          try { ws.close(); } catch {}
        })
        .connect({
          host: srv.host,
          port: srv.port || 22,
          username: srv.username,
          password: cfg.auth?.password,
          privateKey: cfg.auth?.privateKey,
          tryKeyboard: true
        });

    } else {
      // Mesaje ulterioare: resize sau input
      try {
        const msg = JSON.parse(raw.toString());
        if (msg.type === 'resize' && stream) {
          stream.setWindow(msg.rows, msg.cols, msg.cols * 8, msg.rows * 16);
          return;
        }
      } catch {}
      if (stream) stream.write(raw);
    }
  });

  ws.on('close', () => {
    alive = false;
    try { stream?.close(); } catch {}
    try { ssh?.end(); } catch {}
  });
});

// --- start ---
const PORT = process.env.PORT || 3001;
httpServer.listen(PORT, () => console.log(`Backend on :${PORT}`));
