import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { z } from 'zod';
import { customAlphabet } from 'nanoid';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.cwd(), process.env.DATA_DIR) : __dirname;
const SERVERS_PATH = path.join(DATA_DIR, 'servers.json');
const nanoid = customAlphabet('0123456789abcdefghijklmnopqrstuvwxyz', 10);


export const ServerSchema = z.object({
    id: z.string().min(1),
    name: z.string().min(1),
    host: z.string().min(1),
    port: z.number().int().min(1).max(65535).default(22),
    username: z.string().min(1),
    // câmpuri opționale de UX
    tags: z.array(z.string()).optional(),
    note: z.string().optional()
});


export const NewServerSchema = ServerSchema.omit({ id: true }).partial({ port: true });
async function ensureDataDir() {
    await fs.mkdir(DATA_DIR, { recursive: true });
    try { await fs.access(SERVERS_PATH); }
    catch { await fs.writeFile(SERVERS_PATH, '[]', 'utf8'); }
}


async function readJSON() {
    await ensureDataDir();
    const raw = await fs.readFile(SERVERS_PATH, 'utf8');
    try { return JSON.parse(raw); } catch { return []; }
}


async function writeJSONAtomic(data) {
    await ensureDataDir();
    const tmp = SERVERS_PATH + '.tmp';
    await fs.writeFile(tmp, JSON.stringify(data, null, 2), 'utf8');
    await fs.rename(tmp, SERVERS_PATH);
}


// mic mutex in proces pentru a serializa operațiile
let queue = Promise.resolve();
function withLock(fn) {
    const run = queue.then(fn, fn);
    queue = run.catch(() => { });
    return run;
}


export async function listServers() {
    const list = await readJSON();
    return z.array(ServerSchema).safeParse(list).success ? list : [];
}


export async function addServer(input) {
    return withLock(async () => {
        const data = await readJSON();
        const parsed = NewServerSchema.parse(input);
        const id = nanoid();
        const server = { id, port: 22, ...parsed };
        // unicitate aproximativă: nume+host
        if (data.some(s => s.host === server.host && s.username === server.username && s.port === server.port)) {
            throw new Error('Server deja există (host+username+port)');
        }
        const updated = [...data, server];
        await writeJSONAtomic(updated);
        return server;
    });
}


export async function updateServer(id, input) {
    return withLock(async () => {
        const data = await readJSON();
        const idx = data.findIndex(s => s.id === id);
        if (idx === -1) throw new Error('Server inexistent');
        const merged = { ...data[idx], ...input };
        const server = ServerSchema.parse(merged);
        data[idx] = server;
        await writeJSONAtomic(data);
        return server;
    });
}


export async function deleteServer(id) {
    return withLock(async () => {
        const data = await readJSON();
        const idx = data.findIndex(s => s.id === id);
        if (idx === -1) throw new Error('Server inexistent');
        const [removed] = data.splice(idx, 1);
        await writeJSONAtomic(data);
        return removed;
    });
}