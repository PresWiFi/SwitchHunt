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
 *   POST api/bundle                              body: [u32 LE length][JSON][raw installer bytes] -> same reply
 *   GET  api/intunewin/<id>                      -> the package or bundle (deleted once fully downloaded)
 *
 * A bundle is a zip holding the .intunewin plus loose deployment scripts. The JSON names the
 * installer ({ file, app, crc32 }) and carries two lists of small text files: `payloadFiles` go
 * INSIDE the package next to the installer (Install.ps1, Uninstall.ps1), `bundleFiles` sit beside
 * it in the zip (Detect.ps1, README, and Logo.png sent as { name, base64 }). The scripts are written by
 * the page - see src/lib/deployScripts.ts.
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
import { buildIntuneWinFile, localHeader, packagedSize, zipTail, type ExtraFile, type ZipEntry } from './intunewin.ts';
import { crc32 } from 'node:zlib';

const here = fileURLToPath(new URL('.', import.meta.url));
const num = (v: string | undefined, fallback: number) => (v != null && v !== '' && Number.isFinite(Number(v)) ? Number(v) : fallback);

const PORT = num(process.env.PORT, 8080);
const STATIC_DIR = resolve(process.env.STATIC_DIR ?? join(here, '..', 'dist'));
const DATA_DIR = resolve(process.env.DATA_DIR ?? join(tmpdir(), 'switchhunt'));
// Largest installer accepted. Intune's own ceiling for a Win32 app is 30 GB; 0 disables the check.
const MAX_BYTES = num(process.env.MAX_UPLOAD_GB, 30) * 1024 ** 3;
// How long a built package waits to be downloaded before it is swept.
const TTL_MS = num(process.env.PACKAGE_TTL_MINUTES, 60) * 60_000;

interface Pkg {
  path: string; created: number;
  /** Download name and size - of the bundle zip when there is one, else of the package itself. */
  fileName: string; size: number;
  /** Present for a bundle: the zip records that wrap the package file, which is streamed between them. */
  wrap?: { head: Buffer; tail: Buffer };
}
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
// A name ends up as a zip entry and in Detection.xml - keep the leaf only, no path, no control chars.
function leafName(raw: unknown): string {
  const name = basename(String(raw ?? '').replace(/\\/g, '/')).replace(/[\u0000-\u001f]/g, '').trim();
  return name === '.' || name === '..' ? '' : name;
}

interface BuildRequest {
  setupFile: string; appName: string; size: number; crc32: string;
  payloadFiles?: ExtraFile[]; bundleFiles?: ExtraFile[];
}

async function build(req: IncomingMessage, res: ServerResponse, source: AsyncIterable<Uint8Array>, b: BuildRequest): Promise<void> {
  if (!Number.isSafeInteger(b.size) || b.size <= 0) throw new HttpError(400, 'The installer is empty.');
  if (MAX_BYTES && b.size > MAX_BYTES) throw new HttpError(413, `That installer is over this server's ${Math.round(MAX_BYTES / 1024 ** 3)} GB limit (MAX_UPLOAD_GB).`);
  if (!/^[0-9a-f]{1,8}$/i.test(b.crc32)) throw new HttpError(400, 'crc32 (hex) is required.');
  if (!b.setupFile) throw new HttpError(400, 'file (the installer file name) is required.');
  const appName = b.appName.replace(/[\u0000-\u001f]/g, '').trim() || b.setupFile;

  const total = packagedSize(b.setupFile, appName, b.size, b.payloadFiles);
  const free = await statfs(DATA_DIR).then((s) => s.bavail * s.bsize, () => Infinity);
  if (total > free) throw new HttpError(507, `Not enough disk space on the server: the package needs ${Math.ceil(total / 1024 ** 2)} MB, ${Math.floor(free / 1024 ** 2)} MB is free.`);

  const id = randomBytes(16).toString('hex');
  const path = join(DATA_DIR, `${id}.intunewin`);
  const part = `${path}.part`;
  let built: { size: number; crc32: number };
  try {
    built = await buildIntuneWinFile(source, part, { setupFile: b.setupFile, appName, size: b.size, crc32: parseInt(b.crc32, 16), extraFiles: b.payloadFiles });
    await rename(part, path);
  } catch (e) {
    await rm(part, { force: true });
    if (req.destroyed && !req.complete) return;                       // the browser went away mid-upload
    throw new HttpError(400, (e as Error).message);
  }
  const stem = b.setupFile.replace(/\.[^.]+$/, '') || 'package';
  const pkg: Pkg = { path, fileName: `${stem}.intunewin`, size: built.size, created: Date.now() };
  if (b.bundleFiles) {
    // The bundle is never written out: its zip records are kept here and the package file is
    // streamed between them at download time, so a bundle costs no more disk than a package.
    let offset = 0;
    const heads: Buffer[] = [];
    const entries = [...b.bundleFiles, { name: pkg.fileName, data: null }].map((f) => {
      const e: ZipEntry = { name: Buffer.from(f.name, 'utf8'), size: f.data ? f.data.length : built.size, crc: f.data ? crc32(f.data) : built.crc32, offset, utf8: true };
      heads.push(localHeader(e));
      if (f.data) heads.push(Buffer.from(f.data));
      offset += localHeader(e).length + e.size;
      return e;
    });
    pkg.wrap = { head: Buffer.concat(heads), tail: zipTail(entries, offset) };
    pkg.fileName = `${stem}-Intune.zip`;
    pkg.size = pkg.wrap.head.length + built.size + pkg.wrap.tail.length;
  }
  packages.set(id, pkg);
  console.log(`built ${id} ${JSON.stringify(b.setupFile)} ${b.size} -> ${pkg.size} bytes${pkg.wrap ? ' (bundle)' : ''}`);
  json(res, 201, { id, fileName: pkg.fileName, size: pkg.size, url: `api/intunewin/${id}` });
}

// Requiring a non-form content type means a cross-origin page cannot fire an upload at a local
// server blind: the browser has to preflight it, and no CORS headers are ever sent back.
function uploadSize(req: IncomingMessage): number {
  if (!/^application\/octet-stream\b/i.test(req.headers['content-type'] ?? '')) throw new HttpError(415, 'Send the installer as application/octet-stream.');
  const size = Number(req.headers['content-length']);
  if (!Number.isSafeInteger(size) || size <= 0) throw new HttpError(411, 'A Content-Length is required.');
  return size;
}

async function handleBuild(req: IncomingMessage, res: ServerResponse, q: URLSearchParams): Promise<void> {
  const size = uploadSize(req);
  await build(req, res, req, { setupFile: leafName(q.get('file')), appName: q.get('app') ?? '', size, crc32: q.get('crc32') ?? '' });
}

const DRAIN_MAX = 1024 ** 3;
const MAX_META = 8 * 1024 * 1024;   // the JSON in front of a bundle upload: a handful of scripts and a logo
const MAX_FILES = 16;
const MAX_IMAGE = 4 * 1024 * 1024;

/**
 * Files from a bundle request -> named byte buffers. Text files are converted as Windows PowerShell
 * 5.1 wants them; images (the app logo) arrive as base64 and are passed through untouched.
 */
function scriptFiles(list: unknown, taken: Set<string>): ExtraFile[] {
  if (!Array.isArray(list) || list.length > MAX_FILES) throw new HttpError(400, 'Bad file list.');
  return list.map((f) => {
    const name = leafName(f?.name);
    if (!name) throw new HttpError(400, 'Each file needs a name.');
    if (taken.has(name.toLowerCase())) throw new HttpError(400, `Two files are both named ${name}.`);
    taken.add(name.toLowerCase());
    if (typeof f.base64 === 'string') {
      if (!/\.(png|jpe?g)$/i.test(name)) throw new HttpError(400, `${name}: only .png and .jpg files can be sent as binary.`);
      const data = Buffer.from(f.base64, 'base64');
      if (!data.length || data.length > MAX_IMAGE) throw new HttpError(400, `${name} is empty or over ${MAX_IMAGE / 1024 ** 2} MB.`);
      return { name, data };
    }
    if (typeof f.text !== 'string') throw new HttpError(400, 'Each file needs a name and text.');
    const text = f.text.replace(/\r?\n/g, '\r\n');
    // 5.1 reads a .ps1 without a BOM as ANSI and mangles anything non-ASCII in it.
    return { name, data: Buffer.from((/\.ps1$/i.test(name) ? '\ufeff' : '') + text, 'utf8') };
  });
}

async function handleBundle(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const total = uploadSize(req);
  // Peel the length-prefixed JSON off the front of the body; everything after it is the installer.
  // destroyOnReturn: false - a refused bundle must leave the request readable, so the error reply
  // can be delivered (see the drain in the request handler).
  const body = req.iterator({ destroyOnReturn: false });
  let buf = Buffer.alloc(0);
  const need = async (n: number) => {
    while (buf.length < n) {
      const r = await body.next();
      if (r.done) throw new HttpError(400, 'The upload ended before its header.');
      buf = Buffer.concat([buf, r.value]);
    }
  };
  let ended = false;
  const end = async () => { if (!ended) { ended = true; await body.return?.(); } };
  try {
    await need(4);
    const metaLen = buf.readUInt32LE(0);
    if (metaLen > MAX_META) throw new HttpError(400, 'The bundle header is too large.');
    await need(4 + metaLen);
    let meta: Record<string, unknown>;
    try { meta = JSON.parse(buf.toString('utf8', 4, 4 + metaLen)); } catch { throw new HttpError(400, 'The bundle header is not valid JSON.'); }
    const first = buf.subarray(4 + metaLen);
    const installer = (async function* () {
      if (first.length) yield first;
      for (let r = await body.next(); !r.done; r = await body.next()) yield r.value as Uint8Array;
    })();

    const setupFile = leafName(meta.file);
    const taken = new Set([setupFile.toLowerCase()]);
    const payloadFiles = scriptFiles(meta.payloadFiles, taken);
    // Beside the package in the zip; the package's own name is reserved there too.
    const beside = new Set([(setupFile.replace(/\.[^.]+$/, '') || 'package').toLowerCase() + '.intunewin']);
    const bundleFiles = scriptFiles(meta.bundleFiles, beside);
    await build(req, res, installer, {
      setupFile, appName: String(meta.app ?? ''), size: total - 4 - metaLen, crc32: String(meta.crc32 ?? ''), payloadFiles, bundleFiles,
    });
  } finally { await end(); }
}

async function handleDownload(req: IncomingMessage, res: ServerResponse, id: string): Promise<void> {
  const pkg = packages.get(id);
  if (!pkg) throw new HttpError(404, 'That package has expired or was already downloaded. Build it again.');
  const ascii = pkg.fileName.replace(/[^\x20-\x7e]|["\\]/g, '_');
  res.writeHead(200, {
    'Content-Type': pkg.wrap ? 'application/zip' : 'application/octet-stream',
    'Content-Length': pkg.size,
    'Content-Disposition': `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(pkg.fileName)}`,
    'Cache-Control': 'no-store',
  });
  if (req.method === 'HEAD') { res.end(); return; }
  const { wrap } = pkg;
  try {
    if (wrap) await pipeline(async function* () { yield wrap.head; yield* createReadStream(pkg.path); yield wrap.tail; }, res);
    else await pipeline(createReadStream(pkg.path), res);
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
    const api = url.pathname.match(/\/api\/(health|intunewin|bundle)(?:\/([0-9a-f]{32}))?$/);
    const read = req.method === 'GET' || req.method === 'HEAD';
    if (api?.[1] === 'health' && read) return json(res, 200, { ok: true, maxBytes: MAX_BYTES });
    if (api?.[1] === 'intunewin' && !api[2] && req.method === 'POST') return await handleBuild(req, res, url.searchParams);
    if (api?.[1] === 'bundle' && !api[2] && req.method === 'POST') return await handleBundle(req, res);
    if (api?.[1] === 'intunewin' && api[2] && read) return await handleDownload(req, res, api[2]);
    if (api) throw new HttpError(405, 'Method not allowed.');
    if (!read) throw new HttpError(405, 'Method not allowed.');
    await handleStatic(req, res, url.pathname);
  } catch (e) {
    const status = e instanceof HttpError ? e.status : 500;
    if (status === 500) console.error(e);
    if (res.headersSent) { res.destroy(); return; }
    // A browser only reads the reply once it has finished sending, so a refused upload is read to
    // the end and thrown away - otherwise the user sees a dropped connection instead of the reason.
    // Past DRAIN_MAX that costs more than it is worth, and the connection closes with the reply.
    const drain = !req.complete && !req.destroyed && Number(req.headers['content-length']) <= DRAIN_MAX;
    if (drain) req.resume();
    json(res, status, { error: status === 500 ? 'Internal server error.' : (e as Error).message }, req.complete || drain ? {} : { Connection: 'close' });
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
