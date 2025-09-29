import express from 'express';
import http from 'http';
import cors from 'cors';
import dotenv from 'dotenv';
import { WebSocketServer } from 'ws';
import { Client as SSHClient } from 'ssh2';
import fs from 'fs';
import jwt from 'jsonwebtoken';

dotenv.config();


const app = express();
app.use(express.json());
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(',') || true, credentials: true }));


const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws/ssh' });


const USE_AUTH = process.env.USE_AUTH !== 'false';
const JWT_PUBLIC_KEY = process.env.JWT_PUBLIC_KEY;
const ALLOWED = (process.env.ALLOWED_SSH_HOSTS || '').split(',').map(s => s.trim()).filter(Boolean);
const servers = JSON.parse(fs.readFileSync(new URL('./servers.json', import.meta.url)));

function assertAllowedHost(host) {
    if (!ALLOWED.length) return; // dacă nu e setat, nu restricționăm
    if (!ALLOWED.includes(host)) throw new Error(`Host ${host} nu este permis`);
}


function verifyJWT(token) {
    if (!USE_AUTH) return { sub: 'dev' };
    if (!token) throw new Error('Fără token');
    try {
        const decoded = jwt.verify(token, JWT_PUBLIC_KEY, { algorithms: ['RS256', 'HS256'] });
        return decoded;
    } catch (e) {
        throw new Error('JWT invalid');
    }
}


// Endpoint pentru listarea serverelor (UI carduri)
app.get('/api/servers', (req, res) => {
    res.json(servers.map(({ id, name, host, port, username }) => ({ id, name, host, port, username })));
});

wss.on('connection', (ws, req) => {
    let ssh, stream;
    let alive = true;


    ws.on('message', async (raw) => {
        if (!ssh) {
            // Primul mesaj: JSON cu { serverId, cols, rows, auth: { password | privateKey }, token }
            let cfg;
            try { cfg = JSON.parse(raw.toString()); } catch { ws.close(1008, 'Primul mesaj trebuie să fie JSON'); return; }


            // Auth aplicație (JWT)
            try { verifyJWT(cfg.token); } catch (e) { ws.close(1008, e.message); return; }


            const srv = servers.find(s => s.id === cfg.serverId);
            if (!srv) { ws.close(1008, 'Server necunoscut'); return; }
            try { assertAllowedHost(srv.host); } catch (e) { ws.close(1008, e.message); return; }


            ssh = new SSHClient();
            ssh.on('ready', () => {
                ssh.shell({ term: 'xterm-256color', cols: cfg.cols || 80, rows: cfg.rows || 24 }, (err, s) => {
                    if (err) { ws.close(1011, `PTY error: ${err.message}`); return; }
                    stream = s;
                    stream.on('data', d => alive && ws.send(d));
                    stream.stderr?.on('data', d => alive && ws.send(d));
                    stream.on('close', () => { try { ws.close(); } catch { } });
                });
            }).on('error', (e) => {
                try { ws.send(Buffer.from(`\r\n[SSH ERROR] ${e.message}\r\n`)); } catch { }
                try { ws.close(); } catch { }
            }).connect({
                host: srv.host,
                port: srv.port || 22,
                username: srv.username,
                // Doar UNA dintre opțiuni (ideal chei, nu parole)
                password: cfg.auth?.password,
                privateKey: cfg.auth?.privateKey,
                tryKeyboard: true
            });


        } else {
            // Mesaje ulterioare: resize sau input brut
            try {
                const msg = JSON.parse(raw.toString());
                if (msg.type === 'resize' && stream) {
                    stream.setWindow(msg.rows, msg.cols, msg.cols * 8, msg.rows * 16);
                    return;
                }
            } catch (_) { }
            if (stream) stream.write(raw);
        }
    });


    ws.on('close', () => {
        alive = false;
        try { stream?.close(); } catch { }
        try { ssh?.end(); } catch { }
    });
});


const PORT = process.env.PORT || 3001;
server.listen(PORT, () => console.log(`Backend on :${PORT}`));