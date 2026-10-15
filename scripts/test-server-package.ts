/**
 * Tests for the streaming server packager (server/intunewin.ts + server/main.ts).
 *
 *   node scripts/test-server-package.ts                  parity + HTTP round trip (seconds)
 *   node scripts/test-server-package.ts --big 5 out.intunewin
 *       also stream a 5 GB synthetic installer into out.intunewin (ZIP64 path) and decrypt it back.
 *       Needs that much free disk; the file is left in place so other tools can inspect it.
 *
 * The parity test is the important one: with the same keys, the server must produce the exact
 * bytes the in-browser builder does. That builder is the one already proven against Intune.
 */
import { spawn } from 'node:child_process';
import { createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto';
import { appendFile, mkdtemp, open, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { crc32 } from 'node:zlib';
import { buildIntuneWinFile, crc32Combine, packagedSize } from '../server/intunewin.ts';
import { buildIntuneWin } from '../src/lib/intunewin.ts';

let failed = 0;
const check = (ok: boolean, what: string) => { console.log(`${ok ? 'ok  ' : 'FAIL'}  ${what}`); if (!ok) failed++; };
const tmp = await mkdtemp(join(tmpdir(), 'switchhunt-test-'));

// ── crc32Combine against the real thing ──────────────────────────────────────
{
  let ok = true;
  for (const [a, b] of [[0, 1], [1, 0], [32, 48], [1000, 1], [7, 70_001], [65_536, 1_000_003]]) {
    const x = randomBytes(a), y = randomBytes(b);
    ok &&= crc32Combine(crc32(x), crc32(y), b) === crc32(Buffer.concat([x, y]));
  }
  check(ok, 'crc32Combine matches a direct CRC-32 of the concatenation');
}

// ── byte parity with the in-browser builder ──────────────────────────────────
{
  const cases: Array<[string, string, number]> = [
    ['setup.exe', 'Setup', 1], ['setup.exe', 'Setup', 15], ['setup.exe', 'Setup', 16], ['a.msi', 'A & B <"7">', 4097],
    ['Ünïcode installer é.exe', 'Ünïcode ✓', 1_000_000], ['big.exe', 'Big', 3 * 1024 * 1024 + 5],
  ];
  for (const [setupFile, appName, size] of cases) {
    const installer = randomBytes(size);
    const keys = randomBytes(80);
    // Both builders draw 32 (AES key), 32 (MAC key), 16 (IV) in that order - feed them the same bytes.
    const draws = () => { let p = 0; return (n: number) => keys.subarray(p, (p += n)); };
    const real = globalThis.crypto.getRandomValues;
    const next = draws();
    globalThis.crypto.getRandomValues = ((a: Uint8Array) => { a.set(next(a.length)); return a; }) as typeof real;
    const browser = await buildIntuneWin(setupFile, new Uint8Array(installer), appName);
    globalThis.crypto.getRandomValues = real;

    const out = join(tmp, 'parity.intunewin');
    // Uneven chunks, so nothing accidentally depends on AES block alignment of the input.
    const chunks = async function* () { for (let p = 0; p < size; p += 1000) yield installer.subarray(p, p + 1000); };
    const res = await buildIntuneWinFile(chunks(), out, { setupFile, appName, size, crc32: crc32(installer), random: draws() });
    const serverBytes = await readFile(out);
    check(Buffer.compare(serverBytes, browser) === 0 && res.size === serverBytes.length && packagedSize(setupFile, appName, size) === res.size,
      `parity with the browser builder: ${size} bytes, ${JSON.stringify(setupFile)}`);
  }
  let rejected = false;
  try {
    await buildIntuneWinFile((async function* () { yield randomBytes(100); })(), join(tmp, 'bad.intunewin'), { setupFile: 'x.exe', appName: 'x', size: 100, crc32: 1 });
  } catch { rejected = true; }
  check(rejected, 'a stream that does not match its declared CRC-32 is rejected');
}

// ── independent-ish unpack: zip central directory (ZIP64 aware) -> decrypt -> installer ──
interface Entry { name: string; size: number; dataStart: number; }
async function readZipEntries(path: string): Promise<Entry[]> {
  const fh = await open(path, 'r');
  try {
    const { size } = await fh.stat();
    const at = async (pos: number, len: number) => (await fh.read(Buffer.alloc(len), 0, len, pos)).buffer;
    const eocd = await at(size - 22, 22);
    if (eocd.readUInt32LE(0) !== 0x06054b50) throw new Error('no end-of-central-directory record');
    let count = eocd.readUInt16LE(10), cdSize = eocd.readUInt32LE(12), cdStart = eocd.readUInt32LE(16);
    if (cdStart === 0xffffffff) {
      const loc = await at(size - 42, 20);
      if (loc.readUInt32LE(0) !== 0x07064b50) throw new Error('no ZIP64 locator');
      const rec = await at(Number(loc.readBigUInt64LE(8)), 56);
      count = Number(rec.readBigUInt64LE(32)); cdSize = Number(rec.readBigUInt64LE(40)); cdStart = Number(rec.readBigUInt64LE(48));
    }
    const cd = await at(cdStart, cdSize);
    const out: Entry[] = [];
    for (let p = 0, i = 0; i < count; i++) {
      const nameLen = cd.readUInt16LE(p + 28), extraLen = cd.readUInt16LE(p + 30);
      let entrySize = cd.readUInt32LE(p + 24);
      const offset = cd.readUInt32LE(p + 42);
      if (entrySize === 0xffffffff) entrySize = Number(cd.readBigUInt64LE(p + 46 + nameLen + 4));
      const lh = await at(offset, 30);
      out.push({ name: cd.toString('utf8', p + 46, p + 46 + nameLen), size: entrySize, dataStart: offset + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28) });
      p += 46 + nameLen + extraLen;
    }
    return out;
  } finally { await fh.close(); }
}

/** Decrypt a package the way Intune would and hash the installer that comes out. */
async function unpack(path: string, payloadOut?: string): Promise<{ setupFile: string; sha256: string; macOk: boolean; digestOk: boolean; size: number }> {
  const entries = await readZipEntries(path);
  const xmlE = entries.find((e) => e.name.endsWith('Detection.xml'))!;
  const encE = entries.find((e) => e.name.endsWith('IntunePackage.intunewin'))!;
  const fh = await open(path, 'r');
  try {
    const xml = (await fh.read(Buffer.alloc(xmlE.size), 0, xmlE.size, xmlE.dataStart)).buffer.toString('utf8');
    const tag = (t: string) => new RegExp(`<${t}>([^<]*)</${t}>`).exec(xml)![1];
    const b64 = (t: string) => Buffer.from(tag(t), 'base64');
    const head = (await fh.read(Buffer.alloc(48), 0, 48, encE.dataStart)).buffer;
    const hmac = createHmac('sha256', b64('MacKey')).update(head.subarray(32));
    const decipher = createDecipheriv('aes-256-cbc', b64('EncryptionKey'), head.subarray(32));
    const digest = createHash('sha256');   // of the decrypted payload zip
    const inst = createHash('sha256');     // of the installer inside it
    // The payload zip is one STORE entry: [local header][installer][central directory...]. Its size
    // field is 0xffffffff under ZIP64, with the real size in the extra field right after the name.
    let headBuf = Buffer.alloc(0), skip = -1, left = 0, size = 0;
    if (payloadOut) await writeFile(payloadOut, '');
    const feed = async (plain: Buffer) => {
      digest.update(plain);
      if (payloadOut) await appendFile(payloadOut, plain);   // small test packages only
      if (skip < 0) {
        headBuf = Buffer.concat([headBuf, plain]);
        if (headBuf.length < 30) return;
        const nameLen = headBuf.readUInt16LE(26), extraLen = headBuf.readUInt16LE(28);
        if (headBuf.length < 30 + nameLen + extraLen) return;
        left = headBuf.readUInt32LE(18);
        if (left === 0xffffffff) left = Number(headBuf.readBigUInt64LE(30 + nameLen + 4));
        size = left; skip = 0;
        plain = headBuf.subarray(30 + nameLen + extraLen);
      }
      const take = plain.subarray(0, Math.min(left, plain.length));
      inst.update(take); left -= take.length;
    };
    for await (const chunk of fh.createReadStream({ start: encE.dataStart + 48, end: encE.dataStart + encE.size - 1, autoClose: false })) {
      hmac.update(chunk);
      await feed(decipher.update(chunk));
    }
    await feed(decipher.final());
    return {
      setupFile: tag('SetupFile'), size, sha256: inst.digest('hex'),
      macOk: hmac.digest().equals(head.subarray(0, 32)), digestOk: digest.digest('base64') === tag('FileDigest'),
    };
  } finally { await fh.close(); }
}

// ── HTTP round trip against the real server ──────────────────────────────────
{
  const port = 20000 + Math.floor(Math.random() * 20000);
  const data = join(tmp, 'data');
  const child = spawn(process.execPath, [fileURLToPath(new URL('../server/main.ts', import.meta.url))], {
    env: { ...process.env, PORT: String(port), DATA_DIR: data, STATIC_DIR: tmp, MAX_UPLOAD_GB: '0.01' }, stdio: ['ignore', 'pipe', 'inherit'],
  });
  try {
    await new Promise<void>((resolve, reject) => { child.stdout.once('data', () => resolve()); child.once('exit', () => reject(new Error('server exited'))); });
    const base = `http://127.0.0.1:${port}/`;
    const health = await (await fetch(base + 'api/health')).json();
    check(health.ok === true && health.maxBytes === 0.01 * 1024 ** 3, 'GET api/health');

    const installer = randomBytes(5 * 1024 * 1024 + 123);
    const post = (body: Uint8Array, crc: number, headers: Record<string, string> = { 'Content-Type': 'application/octet-stream' }) =>
      fetch(`${base}api/intunewin?${new URLSearchParams({ file: 'C:\\evil\\..\\My App Setup.exe', app: 'My App', crc32: crc.toString(16) })}`, { method: 'POST', headers, body: body as BodyInit });

    check((await post(installer, crc32(installer), { 'Content-Type': 'text/plain' })).status === 415, 'POST without application/octet-stream is refused (415)');
    check((await post(installer, 12345)).status === 400, 'POST with a wrong CRC-32 is refused (400)');
    check((await post(randomBytes(11 * 1024 * 1024), 0)).status === 413, 'POST over MAX_UPLOAD_GB is refused (413)');
    check((await readdir(data)).length === 0, 'refused uploads leave nothing on disk');

    const built = await (await post(installer, crc32(installer))).json();
    check(built.fileName === 'My App Setup.intunewin' && /^api\/intunewin\/[0-9a-f]{32}$/.test(built.url), 'POST api/intunewin builds a package and strips the path from the name');
    const dl = await fetch(base + built.url);
    const pkg = Buffer.from(await dl.arrayBuffer());
    const out = join(tmp, 'http.intunewin');
    await writeFile(out, pkg);
    const u = await unpack(out);
    check(pkg.length === built.size && /filename="My App Setup\.intunewin"/.test(dl.headers.get('content-disposition') ?? ''), 'download has the announced size and file name');
    check(u.macOk && u.digestOk && u.setupFile === 'My App Setup.exe' && u.sha256 === createHash('sha256').update(installer).digest('hex'),
      'downloaded package decrypts back to the uploaded installer (HMAC + digest valid)');
    await new Promise((r) => setTimeout(r, 300));
    check((await readdir(data)).length === 0 && (await fetch(base + built.url)).status === 404, 'package is deleted from the server after download');

    // Bundle: [u32 LE length][JSON][installer] -> zip of the package (scripts inside) + loose files.
    const bundleBody = (meta: object) => {
      const j = Buffer.from(JSON.stringify(meta));
      const len = Buffer.alloc(4); len.writeUInt32LE(j.length);
      return fetch(base + 'api/bundle', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: Buffer.concat([len, j, installer]) as BodyInit });
    };
    const logo = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x0a, 0x00, 0xff]); // its CR/LF bytes must survive
    const meta = {
      file: 'My App Setup.exe', app: 'My App', crc32: crc32(installer).toString(16),
      payloadFiles: [{ name: 'Install.ps1', text: 'Write-Output "é"\nexit 0\n' }, { name: 'Uninstall.ps1', text: 'exit 0' }],
      bundleFiles: [{ name: 'Detect.ps1', text: 'exit 1' }, { name: '..\\..\\README.txt', text: 'read me' }, { name: 'Logo.png', base64: logo.toString('base64') }],
    };
    check((await bundleBody({ ...meta, bundleFiles: [{ name: 'Detect.ps1', base64: logo.toString('base64') }] })).status === 400, 'a binary bundle file that is not an image is refused (400)');
    check((await bundleBody({ ...meta, payloadFiles: [{ name: 'my app setup.EXE', text: 'x' }] })).status === 400, 'a bundle script that would overwrite the installer is refused (400)');
    const b = await (await bundleBody(meta)).json();
    const zipPath = join(tmp, 'bundle.zip');
    const zipBytes = Buffer.from(await (await fetch(base + b.url)).arrayBuffer());
    await writeFile(zipPath, zipBytes);
    const outer = await readZipEntries(zipPath);
    const slice = (e: Entry) => zipBytes.subarray(e.dataStart, e.dataStart + e.size);
    check(b.fileName === 'My App Setup-Intune.zip' && zipBytes.length === b.size
      && outer.map((e) => e.name).join('|') === 'Detect.ps1|README.txt|Logo.png|My App Setup.intunewin'
      && slice(outer[0]).toString() === '\ufeffexit 1' && slice(outer[1]).toString() === 'read me' && slice(outer[2]).equals(logo),
      'bundle zip holds the loose files (path stripped, .ps1 with BOM, logo byte-for-byte) and the package');
    const inner = join(tmp, 'bundle.intunewin'), payload = join(tmp, 'payload.zip');
    await writeFile(inner, slice(outer[3]));
    const bu = await unpack(inner, payload);
    const pz = await readFile(payload);
    const pe = await readZipEntries(payload);
    check(bu.macOk && bu.digestOk && bu.sha256 === createHash('sha256').update(installer).digest('hex')
      && pe.map((e) => e.name).join('|') === 'My App Setup.exe|Install.ps1|Uninstall.ps1'
      && pz.subarray(pe[1].dataStart, pe[1].dataStart + pe[1].size).toString() === '\ufeffWrite-Output "é"\r\nexit 0\r\n',
      'package inside the bundle decrypts to the installer plus Install.ps1 / Uninstall.ps1 (CRLF, BOM)');
    await new Promise((r) => setTimeout(r, 300));
    check((await readdir(data)).length === 0, 'bundle is deleted from the server after download');
  } finally { child.kill(); }
}

// ── opt-in: multi-GB ZIP64 package ───────────────────────────────────────────
const bigAt = process.argv.indexOf('--big');
if (bigAt > 0) {
  const gb = Number(process.argv[bigAt + 1]);
  const out = process.argv[bigAt + 2];
  const size = Math.floor(gb * 1024 ** 3) + 12345;
  // Deterministic, incompressible-enough data that can be generated twice: once for the CRC and
  // SHA the packager needs up front, once as the "upload".
  const block = randomBytes(8 * 1024 * 1024);
  const gen = async function* () {
    for (let p = 0, i = 0; p < size; p += block.length, i++) {
      block.writeUInt32LE(i, 0);
      yield block.subarray(0, Math.min(block.length, size - p));
    }
  };
  let crc = 0;
  const sha = createHash('sha256');
  for await (const c of gen()) { crc = crc32(c, crc); sha.update(c); }
  const t0 = Date.now();
  const res = await buildIntuneWinFile(gen(), out, { setupFile: 'huge-installer.exe', appName: 'Huge', size, crc32: crc });
  const secs = (Date.now() - t0) / 1000;
  console.log(`      built ${(res.size / 1024 ** 3).toFixed(2)} GB in ${secs.toFixed(1)} s (${(size / 1024 ** 2 / secs).toFixed(0)} MB/s), rss ${(process.memoryUsage().rss / 1024 ** 2).toFixed(0)} MB`);
  const u = await unpack(out);
  check(u.macOk && u.digestOk && u.size === size && u.sha256 === sha.digest('hex'), `${gb} GB package (ZIP64) decrypts back to the original installer`);
  console.log(`      installer sha256 ${u.sha256}  size ${size}`);
}

await rm(tmp, { recursive: true, force: true });
console.log(failed ? `${failed} FAILED` : 'all passed');
process.exit(failed ? 1 : 0);
