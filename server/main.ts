/**
 * SwitchHunt server: serves the static site and builds .intunewin packages on disk.
 *
 * The page still does all the ANALYSIS in the browser. What moves here is packaging: the browser
 * streams the installer up, this process encrypts it straight to a file under DATA_DIR, and the
 * browser downloads the result. Nothing is held in memory on either side, so package size is
 * bounded by disk, not by a browser tab.
 *
 *   GET  api/health                              -> { ok, maxBytes }
 *   POST api/intunewin?file=&app=&crc32=<hex>    body: raw installer bytes -> { id, fileName, size, url }
 *   GET  api/intunewin/<id>                      -> the package (deleted once fully downloaded)
 *
 * No dependencies beyond Node itself. There is NO authentication - run it on a network you trust
 * or put it behind a reverse proxy that adds some.
 */
import { createReadStream } from 'node:fs';
import { mkdir, readdir, rename, rm, stat, statfs } from 'node:fs/promises';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { basename, extname, join, normalize, resolve, sep } from 'node:path';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { buildIntuneWinFile, packagedSize } from './intunewin.ts';

const here = fileURLToPath(new URL('.', import.meta.url));
const num = (v: string | undefined, fallback: number) => (v != null && v !== '' && Number.isFinite(Number(v)) ? Number(v) : fallback);

const PORT = num(process.env.PORT, 8080);
const STATIC_DIR = resolve(process.env.STATIC_DIR ?? join(here, '..', 'dist'));
const DATA_DIR = resolve(process.env.DATA_DIR ?? join(tmpdir(), 'switchhunt'));
// Largest installer accepted. Intune's own ceiling for a Win32 app is 30 GB; 0 disables the check.
const MAX_BYTES = num(process.env.MAX_UPLOAD_GB, 30) * 1024 ** 3;
// How long a built package waits to be downloaded before it is swept.
const TTL_MS = num(process.env.PACKAGE_TTL_MINUTES, 60) * 60_000;

interface Pkg { path: string; fileName: string; size: number; created: number; }
const packages = new Map<string, Pkg>();
const OURS = /^[0-9a-f]{32}\.intunewin(\.part)?$/;

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) { super(message); this.status = status; }
}

function json(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(text), 'Cache-Control': 'no-store', ...extra });
  res.end(text);
}

// ── packaging ────────────────────────────────────────────────────────────────
async function handleBuild(req: IncomingMessage, res: ServerResponse, q: URLSearchParams): Promise<void> {
  // Requiring a non-form content type means a cross-origin page cannot fire this at a local server
  // blind: the browser has to preflight it, and no CORS headers are ever sent back.
  if (!/^application\/octet-stream\b/i.test(req.headers['content-type'] ?? '')) throw new HttpError(415, 'Send the installer as application/octet-stream.');
  const size = Number(req.headers['content-length']);
  if (!Number.isSafeInteger(size) || size <= 0) throw new HttpError(411, 'A Content-Length is required.');
  if (MAX_BYTES && size > MAX_BYTES) throw new HttpError(413, `That installer is over this server's ${Math.round(MAX_BYTES / 1024 ** 3)} GB limit (MAX_UPLOAD_GB).`);
  if (!/^[0-9a-f]{1,8}$/i.test(q.get('crc32') ?? '')) throw new HttpError(400, 'crc32 (hex) is required.');

  // The name ends up as a zip entry and in Detection.xml - keep the leaf only, no path, no control chars.
  const setupFile = basename((q.get('file') ?? '').replace(/\\/g, '/')).replace(/[\u0000-\u001f]/g, '').trim();
  if (!setupFile || setupFile === '.' || setupFile === '..') throw new HttpError(400, 'file (the installer file name) is required.');
  const appName = (q.get('app') ?? '').replace(/[\u0000-\u001f]/g, '').trim() || setupFile;

  const total = packagedSize(setupFile, appName, size);
  const free = await statfs(DATA_DIR).then((s) => s.bavail * s.bsize, () => Infinity);
  if (total > free) throw new HttpError(507, `Not enough disk space on the server: the package needs ${Math.ceil(total / 1024 ** 2)} MB, ${Math.floor(free / 1024 ** 2)} MB is free.`);

  const id = randomBytes(16).toString('hex');
  const path = join(DATA_DIR, `${id}.intunewin`);
  const part = `${path}.part`;
  try {
    await buildIntuneWinFile(req, part, { setupFile, appName, size, crc32: parseInt(q.get('crc32')!, 16) });
    await rename(part, path);
  } catch (e) {
    await rm(part, { force: true });
    if (req.destroyed && !req.complete) return;                       // the browser went away mid-upload
    throw new HttpError(400, (e as Error).message);
  }
  const fileName = (setupFile.replace(/\.[^.]+$/, '') || 'package') + '.intunewin';
  packages.set(id, { path, fileName, size: total, created: Date.now() });
  console.log(`built ${id} ${JSON.stringify(setupFile)} ${size} -> ${total} bytes`);
  json(res, 201, { id, fileName, size: total, url: `api/intunewin/${id}` });
}

async function handleDownload(req: IncomingMessage, res: ServerResponse, id: string): Promise<void> {
  const pkg = packages.get(id);
  if (!pkg) throw new HttpError(404, 'That package has expired or was already downloaded. Build it again.');
  const ascii = pkg.fileName.replace(/[^\x20-\x7e]|["\\]/g, '_');
  res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Content-Length': pkg.size,
    'Content-Disposition': `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(pkg.fileName)}`,
    'Cache-Control': 'no-store',
  });
  if (req.method === 'HEAD') { res.end(); return; }
  try {
    await pipeline(createReadStream(pkg.path), res);
  } catch {
    return;   // cancelled or dropped - keep the package so the download can be retried until the TTL
  }
  packages.delete(id);
  await rm(pkg.path, { force: true });
}

async function sweep(): Promise<void> {
  for (const [id, pkg] of packages) {
    if (Date.now() - pkg.created < TTL_MS) continue;
    packages.delete(id);
    await rm(pkg.path, { force: true });
  }
}

// ── static site ──────────────────────────────────────────────────────────────
const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml', '.ico': 'image/x-icon', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.webp': 'image/webp', '.woff2': 'font/woff2',
  '.ps1': 'text/plain; charset=utf-8', '.cmd': 'text/plain; charset=utf-8',
};

async function handleStatic(req: IncomingMessage, res: ServerResponse, pathname: string): Promise<void> {
  let decoded: string;
  try { decoded = decodeURIComponent(pathname); } catch { throw new HttpError(400, 'Bad path.'); }
  let file = normalize(join(STATIC_DIR, decoded));
  if (file !== STATIC_DIR && !file.startsWith(STATIC_DIR + sep)) throw new HttpError(404, 'Not found.');
  let info = await stat(file).catch(() => null);
  if (info?.isDirectory()) { file = join(file, 'index.html'); info = await stat(file).catch(() => null); }
  if (!info?.isFile()) throw new HttpError(404, 'Not found.');
  res.writeHead(200, {
    'Content-Type': TYPES[extname(file).toLowerCase()] ?? 'application/octet-stream',
    'Content-Length': info.size,
    // Astro content-hashes everything under _astro/, safe to cache forever.
    'Cache-Control': pathname.includes('/_astro/') ? 'public, max-age=31536000, immutable' : 'no-cache',
    'X-Content-Type-Options': 'nosniff',
  });
  if (req.method === 'HEAD') { res.end(); return; }
  await pipeline(createReadStream(file), res).catch(() => {});
}

// ── routing ──────────────────────────────────────────────────────────────────
const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const api = url.pathname.match(/\/api\/(health|intunewin)(?:\/([0-9a-f]{32}))?$/);
    const read = req.method === 'GET' || req.method === 'HEAD';
    if (api?.[1] === 'health' && read) return json(res, 200, { ok: true, maxBytes: MAX_BYTES });
    if (api?.[1] === 'intunewin' && !api[2] && req.method === 'POST') return await handleBuild(req, res, url.searchParams);
    if (api?.[1] === 'intunewin' && api[2] && read) return await handleDownload(req, res, api[2]);
    if (api) throw new HttpError(405, 'Method not allowed.');
    if (!read) throw new HttpError(405, 'Method not allowed.');
    await handleStatic(req, res, url.pathname);
  } catch (e) {
    const status = e instanceof HttpError ? e.status : 500;
    if (status === 500) console.error(e);
    if (res.headersSent) { res.destroy(); return; }
    // An upload refused part-way cannot be drained cheaply (it may be gigabytes), so the connection closes with the reply.
    json(res, status, { error: status === 500 ? 'Internal server error.' : (e as Error).message }, req.complete ? {} : { Connection: 'close' });
  }
});

// Node's default gives a request 5 minutes to arrive in full, which a multi-GB upload on a slow
// link will not make. Slow-header protection (headersTimeout) is unaffected.
server.requestTimeout = 0;

await mkdir(DATA_DIR, { recursive: true });
// Packages are tracked in memory, so anything left from a previous run is unreachable - clear it.
for (const f of await readdir(DATA_DIR)) if (OURS.test(f)) await rm(join(DATA_DIR, f), { force: true });
setInterval(() => void sweep(), 60_000).unref();

server.listen(PORT, () => {
  console.log(`SwitchHunt server on :${PORT}  site=${STATIC_DIR}  data=${DATA_DIR}  max=${MAX_BYTES ? Math.round(MAX_BYTES / 1024 ** 3) + ' GB' : 'unlimited'}`);
});
for (const sig of ['SIGINT', 'SIGTERM'] as const) process.on(sig, () => { server.close(); process.exit(0); });
