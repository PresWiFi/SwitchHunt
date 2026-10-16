/**
 * Open a .intunewin the way Intune does, and report what is inside and whether it is sound.
 *
 * Used twice: on every package the server builds, before it is offered for download (so a packager
 * bug can never ship a package that Intune would reject), and on any .intunewin uploaded to
 * api/inspect - one from IntuneWinAppUtil.exe included - to see what it would install.
 *
 * Checks, in order: the outer zip and Detection.xml are readable; the HMAC over IV + ciphertext
 * matches <Mac>; the decrypted payload's SHA-256 matches <FileDigest> and its size matches
 * <UnencryptedContentSize>; every file in the payload zip has the CRC-32 its header claims; and
 * <SetupFile> is among them. Handles STORE and DEFLATE entries and ZIP64, so it reads what
 * IntuneWinAppUtil writes as well as what this server writes.
 *
 * The decrypted payload is written to a temporary file next to the package (and deleted): a payload
 * zip is only readable from its central directory, at the end. Memory stays at a few chunks.
 */
import { createDecipheriv, createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { open, rm, type FileHandle } from 'node:fs/promises';
import { Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { crc32, createInflateRaw } from 'node:zlib';

export interface InspectResult {
  ok: boolean;
  /** What failed, in plain words. Empty when ok. */
  problems: string[];
  /** The checks that passed, in plain words. */
  passed: string[];
  appName?: string;
  setupFile?: string;
  files: Array<{ name: string; size: number; crcOk: boolean }>;
  /** Text of small .ps1/.cmd/.bat/.txt files in the payload - shows what the package will run. */
  scripts: Record<string, string>;
}

interface ZipEntry { name: string; method: number; crc: number; compSize: number; size: number; localOffset: number; }

const MAX_SCRIPT = 256 * 1024;

/** The central directory of a zip file (ZIP64 aware). */
async function readCentral(fh: FileHandle, fileSize: number): Promise<ZipEntry[]> {
  const at = async (pos: number, len: number) => (await fh.read(Buffer.alloc(len), 0, len, pos)).buffer;
  // The end record is 22 bytes plus a comment of up to 64 KB.
  const tailLen = Math.min(fileSize, 22 + 0xffff);
  const tail = await at(fileSize - tailLen, tailLen);
  let e = -1;
  for (let i = tail.length - 22; i >= 0; i--) if (tail.readUInt32LE(i) === 0x06054b50) { e = i; break; }
  if (e < 0) throw new Error('it is not a zip file (no end-of-central-directory record)');
  let count = tail.readUInt16LE(e + 10), cdSize = tail.readUInt32LE(e + 12), cdStart = tail.readUInt32LE(e + 16);
  if (cdStart === 0xffffffff || count === 0xffff || cdSize === 0xffffffff) {
    const locPos = fileSize - tailLen + e - 20;
    const loc = await at(locPos, 20);
    if (loc.readUInt32LE(0) !== 0x07064b50) throw new Error('its ZIP64 locator is missing');
    const rec = await at(Number(loc.readBigUInt64LE(8)), 56);
    if (rec.readUInt32LE(0) !== 0x06064b50) throw new Error('its ZIP64 end record is missing');
    count = Number(rec.readBigUInt64LE(32)); cdSize = Number(rec.readBigUInt64LE(40)); cdStart = Number(rec.readBigUInt64LE(48));
  }
  if (cdStart + cdSize > fileSize || cdSize > 64 * 1024 * 1024) throw new Error('its central directory is out of bounds');
  const cd = await at(cdStart, cdSize);
  const out: ZipEntry[] = [];
  for (let p = 0, i = 0; i < count; i++) {
    if (p + 46 > cd.length || cd.readUInt32LE(p) !== 0x02014b50) throw new Error('its central directory is damaged');
    const flags = cd.readUInt16LE(p + 8);
    const nameLen = cd.readUInt16LE(p + 28), extraLen = cd.readUInt16LE(p + 30), commentLen = cd.readUInt16LE(p + 32);
    let compSize = cd.readUInt32LE(p + 20), size = cd.readUInt32LE(p + 24), localOffset = cd.readUInt32LE(p + 42);
    // ZIP64 extra: only the fields whose 32-bit slot overflowed, in this order.
    for (let x = p + 46 + nameLen; x + 4 <= p + 46 + nameLen + extraLen;) {
      const id = cd.readUInt16LE(x), len = cd.readUInt16LE(x + 2);
      if (id === 0x0001) {
        let f = x + 4;
        if (size === 0xffffffff) { size = Number(cd.readBigUInt64LE(f)); f += 8; }
        if (compSize === 0xffffffff) { compSize = Number(cd.readBigUInt64LE(f)); f += 8; }
        if (localOffset === 0xffffffff) { localOffset = Number(cd.readBigUInt64LE(f)); }
      }
      x += 4 + len;
    }
    const nameBytes = cd.subarray(p + 46, p + 46 + nameLen);
    const name = flags & 0x0800 ? nameBytes.toString('utf8') : nameBytes.toString('latin1');
    out.push({ name, method: cd.readUInt16LE(p + 10), crc: cd.readUInt32LE(p + 16), compSize, size, localOffset });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

/** A readable stream of one entry's (uncompressed) bytes. */
async function entryStream(fh: FileHandle, path: string, e: ZipEntry): Promise<NodeJS.ReadableStream> {
  const lh = (await fh.read(Buffer.alloc(30), 0, 30, e.localOffset)).buffer;
  if (lh.readUInt32LE(0) !== 0x04034b50) throw new Error(`the local header of ${e.name} is damaged`);
  const start = e.localOffset + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
  if (e.method !== 0 && e.method !== 8) throw new Error(`${e.name} uses an unsupported compression method (${e.method})`);
  const raw = e.compSize ? createReadStream(path, { start, end: start + e.compSize - 1 }) : createReadStream(path, { start, end: start - 1 });
  return e.method === 8 ? raw.pipe(createInflateRaw()) : raw;
}

/** CRC-32 and length of a stream, plus its text when it is small. */
async function digestStream(s: NodeJS.ReadableStream, keepText: boolean): Promise<{ crc: number; size: number; text?: string }> {
  let crc = 0, size = 0;
  const kept: Buffer[] = [];
  for await (const chunk of s as AsyncIterable<Buffer>) {
    crc = crc32(chunk, crc);
    size += chunk.length;
    if (keepText && size <= MAX_SCRIPT) kept.push(chunk);
  }
  return { crc, size, text: keepText && size <= MAX_SCRIPT ? Buffer.concat(kept).toString('utf8').replace(/^﻿/, '') : undefined };
}

export async function inspectIntuneWin(path: string): Promise<InspectResult> {
  const r: InspectResult = { ok: false, problems: [], passed: [], files: [], scripts: {} };
  const tmp = `${path}.payload`;
  let fh: FileHandle | null = null;
  try {
    fh = await open(path, 'r');
    const { size: fileSize } = await fh.stat();
    const outer = await readCentral(fh, fileSize);
    const xmlE = outer.find((e) => /(^|\/)Metadata\/Detection\.xml$/i.test(e.name));
    const encE = outer.find((e) => /(^|\/)Contents\/[^/]+\.intunewin$/i.test(e.name));
    if (!xmlE || !encE) throw new Error('it has no IntuneWinPackage/Metadata/Detection.xml or no encrypted Contents file - not a .intunewin');

    const xml = (await digestStream(await entryStream(fh, path, xmlE), true)).text ?? '';
    const tag = (t: string) => new RegExp(`<${t}>([^<]*)</${t}>`).exec(xml)?.[1];
    const unesc = (s?: string) => s?.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
    r.appName = unesc(tag('Name'));
    r.setupFile = unesc(tag('SetupFile'));
    const key = Buffer.from(tag('EncryptionKey') ?? '', 'base64'), macKey = Buffer.from(tag('MacKey') ?? '', 'base64');
    const iv = Buffer.from(tag('InitializationVector') ?? '', 'base64'), mac = Buffer.from(tag('Mac') ?? '', 'base64');
    const digest = tag('FileDigest'), declaredSize = Number(tag('UnencryptedContentSize'));
    if (key.length !== 32 || macKey.length !== 32 || iv.length !== 16 || mac.length !== 32 || !digest) throw new Error('Detection.xml is missing its encryption keys');
    r.passed.push('Detection.xml is readable and carries the encryption keys');

    // [HMAC 32][IV 16][ciphertext]: HMAC over IV + ciphertext, then decrypt to a temporary file.
    const hmac = createHmac('sha256', macKey);
    const sha = createHash('sha256');
    const decipher = createDecipheriv('aes-256-cbc', key, iv);
    // Filled in by the stream transforms below, so kept in an object rather than in narrowed lets.
    const got = { head: Buffer.alloc(0), mac: null as Buffer | null, iv: null as Buffer | null, plainSize: 0 };
    const split = new Transform({
      transform(chunk: Buffer, _enc, done) {
        if (!got.iv) {
          got.head = Buffer.concat([got.head, chunk]);
          if (got.head.length < 48) return done();
          got.mac = got.head.subarray(0, 32); got.iv = got.head.subarray(32, 48);
          hmac.update(got.iv);
          chunk = got.head.subarray(48);
        }
        hmac.update(chunk);
        done(null, chunk);
      },
    });
    const count = new Transform({ transform(chunk: Buffer, _e, done) { sha.update(chunk); got.plainSize += chunk.length; done(null, chunk); } });
    try {
      await pipeline(await entryStream(fh, path, encE), split, decipher, count, createWriteStream(tmp));
    } catch (e) {
      if (!got.mac) throw new Error('the encrypted content is truncated');
      // A bad key or a corrupted tail shows up as a padding error - report it after the HMAC check.
      r.problems.push(`the content does not decrypt (${(e as Error).message})`);
    }
    if (!got.mac || !got.iv) throw new Error('the encrypted content is truncated');
    const plainSize = got.plainSize;
    if (!timingSafeEqual(hmac.digest(), mac) || !timingSafeEqual(got.mac, mac)) r.problems.push('the HMAC does not match - the content is damaged or the keys belong to a different package');
    else r.passed.push('HMAC-SHA256 over the encrypted content matches');
    if (!got.iv.equals(iv)) r.problems.push('the IV in the content differs from the one in Detection.xml');
    if (r.problems.length) return r;
    if (sha.digest('base64') !== digest) r.problems.push('the SHA-256 of the decrypted content does not match FileDigest');
    else r.passed.push('decrypts, and the SHA-256 of the content matches FileDigest');
    if (Number.isFinite(declaredSize) && declaredSize !== plainSize) r.problems.push(`the content is ${plainSize} bytes, Detection.xml says ${declaredSize}`);

    // The payload zip: every file's CRC-32, and the text of the small scripts.
    const pfh = await open(tmp, 'r');
    try {
      const inner = await readCentral(pfh, plainSize);
      for (const e of inner) {
        if (e.name.endsWith('/')) continue;
        const keep = /\.(ps1|cmd|bat|txt|json|xml|ini)$/i.test(e.name) && e.size <= MAX_SCRIPT;
        const d = await digestStream(await entryStream(pfh, tmp, e), keep);
        const crcOk = d.crc === e.crc && d.size === e.size;
        r.files.push({ name: e.name, size: d.size, crcOk });
        if (!crcOk) r.problems.push(`${e.name} is damaged (CRC-32 or size mismatch)`);
        if (d.text != null) r.scripts[e.name] = d.text;
      }
    } finally { await pfh.close(); }
    if (r.files.length && r.files.every((f) => f.crcOk)) r.passed.push(`all ${r.files.length} file(s) inside pass their CRC-32 check`);
    if (r.setupFile && !r.files.some((f) => f.name.toLowerCase() === r.setupFile!.toLowerCase())) {
      r.problems.push(`the setup file ${r.setupFile} named in Detection.xml is not in the package`);
    }
    r.ok = r.problems.length === 0;
  } catch (e) {
    r.problems.push((e as Error).message);
  } finally {
    await fh?.close();
    await rm(tmp, { force: true });
  }
  return r;
}
