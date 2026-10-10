/**
 * Streaming .intunewin packager for the SwitchHunt server.
 *
 * Produces the same package as the in-browser builder (src/lib/intunewin.ts) - byte for byte, given
 * the same keys - but never holds the installer in memory: the upload is zipped, hashed and
 * AES-256-CBC encrypted chunk by chunk and written straight to a file on disk. Memory use is a few
 * chunks regardless of installer size, so the only limits are disk space and Intune's own cap.
 *
 * Format (see src/lib/intunewin.ts for the sources):
 *   .intunewin = zip {
 *     IntuneWinPackage/Metadata/Detection.xml          (plaintext, holds the keys)
 *     IntuneWinPackage/Contents/IntunePackage.intunewin (encrypted payload)
 *   }
 *   encrypted payload = [HMAC-SHA256: 32B][IV: 16B][AES-256-CBC(payloadZip), PKCS7]
 *
 * Two things in that layout are only known once the last byte has been encrypted, yet sit BEFORE
 * the ciphertext in the file: the HMAC, and Detection.xml (which carries the HMAC and the digest).
 * Both have a length that is known up front, so they are written as zero-filled placeholders and
 * patched in place at the end. The one thing that cannot be patched is the payload zip's own local
 * header - it is encrypted, and CBC chains forward - so the installer's CRC-32 has to be supplied
 * by the caller before the first byte arrives. It is verified against the stream afterwards.
 *
 * Past 4 GB the 32-bit zip fields overflow; both zips switch to ZIP64 records only when they have to,
 * so anything the in-browser builder could also produce stays identical to it.
 */
import { createCipheriv, createHash, createHmac, randomBytes } from 'node:crypto';
import { open } from 'node:fs/promises';
import { crc32 } from 'node:zlib';

const U32_MAX = 0xffffffff;
const XML_ENTRY = 'IntuneWinPackage/Metadata/Detection.xml';
const ENC_ENTRY = 'IntuneWinPackage/Contents/IntunePackage.intunewin';

// ── STORE zip records (ZIP64 only when a field overflows) ────────────────────
interface ZipEntry { name: Buffer; size: number; crc: number; offset: number; }

function zip64Sizes(size: number): Buffer {
  const x = Buffer.alloc(20);
  x.writeUInt16LE(0x0001, 0);
  x.writeUInt16LE(16, 2);
  x.writeBigUInt64LE(BigInt(size), 4);   // uncompressed
  x.writeBigUInt64LE(BigInt(size), 12);  // compressed (STORE: the same)
  return x;
}

function localHeader(e: ZipEntry): Buffer {
  const z64 = e.size >= U32_MAX;
  const extra = z64 ? zip64Sizes(e.size) : Buffer.alloc(0);
  const h = Buffer.alloc(30);
  h.writeUInt32LE(0x04034b50, 0);
  h.writeUInt16LE(z64 ? 45 : 20, 4);      // version needed
  h.writeUInt16LE(0, 8);                  // method: store
  h.writeUInt16LE(0x21, 12);              // mod date (1980-01-01, fixed - same as the browser build)
  h.writeUInt32LE(e.crc, 14);
  h.writeUInt32LE(z64 ? U32_MAX : e.size, 18);
  h.writeUInt32LE(z64 ? U32_MAX : e.size, 22);
  h.writeUInt16LE(e.name.length, 26);
  h.writeUInt16LE(extra.length, 28);
  return Buffer.concat([h, e.name, extra]);
}

function centralHeader(e: ZipEntry): Buffer {
  const bigSize = e.size >= U32_MAX;
  const bigOffset = e.offset >= U32_MAX;
  let extra = Buffer.alloc(0);
  if (bigSize || bigOffset) {
    const fields: Buffer[] = [];
    if (bigSize) fields.push(zip64Sizes(e.size).subarray(4));
    if (bigOffset) { const o = Buffer.alloc(8); o.writeBigUInt64LE(BigInt(e.offset)); fields.push(o); }
    const body = Buffer.concat(fields);
    const head = Buffer.alloc(4);
    head.writeUInt16LE(0x0001, 0);
    head.writeUInt16LE(body.length, 2);
    extra = Buffer.concat([head, body]);
  }
  const z64 = bigSize || bigOffset;
  const h = Buffer.alloc(46);
  h.writeUInt32LE(0x02014b50, 0);
  h.writeUInt16LE(z64 ? 45 : 20, 4);      // version made by
  h.writeUInt16LE(z64 ? 45 : 20, 6);      // version needed
  h.writeUInt16LE(0, 10);                 // method: store
  h.writeUInt16LE(0x21, 14);
  h.writeUInt32LE(e.crc, 16);
  h.writeUInt32LE(bigSize ? U32_MAX : e.size, 20);
  h.writeUInt32LE(bigSize ? U32_MAX : e.size, 24);
  h.writeUInt16LE(e.name.length, 28);
  h.writeUInt16LE(extra.length, 30);
  h.writeUInt32LE(bigOffset ? U32_MAX : e.offset, 42); // local header offset
  return Buffer.concat([h, e.name, extra]);
}

/** Central directory + end records for a zip whose entries end at `centralStart`. */
function zipTail(entries: ZipEntry[], centralStart: number): Buffer {
  const central = Buffer.concat(entries.map(centralHeader));
  const z64 = centralStart >= U32_MAX || entries.some((e) => e.size >= U32_MAX || e.offset >= U32_MAX);
  const parts: Buffer[] = [central];
  if (z64) {
    const rec = Buffer.alloc(56);
    rec.writeUInt32LE(0x06064b50, 0);
    rec.writeBigUInt64LE(44n, 4);         // size of the rest of this record
    rec.writeUInt16LE(45, 12);            // version made by
    rec.writeUInt16LE(45, 14);            // version needed
    rec.writeBigUInt64LE(BigInt(entries.length), 24);
    rec.writeBigUInt64LE(BigInt(entries.length), 32);
    rec.writeBigUInt64LE(BigInt(central.length), 40);
    rec.writeBigUInt64LE(BigInt(centralStart), 48);
    const loc = Buffer.alloc(20);
    loc.writeUInt32LE(0x07064b50, 0);
    loc.writeBigUInt64LE(BigInt(centralStart + central.length), 8); // where the ZIP64 record starts
    loc.writeUInt32LE(1, 16);             // total disks
    parts.push(rec, loc);
  }
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(central.length, 12);
  eocd.writeUInt32LE(Math.min(centralStart, U32_MAX), 16);
  parts.push(eocd);
  return Buffer.concat(parts);
}

// ── CRC-32 of a concatenation, from the two halves' CRCs (zlib's crc32_combine) ──
// The encrypted entry's CRC covers HMAC ‖ IV ‖ ciphertext, but the HMAC only exists after the
// ciphertext has been written. Combining avoids re-reading a multi-GB file just to checksum it.
function gf2Times(mat: Uint32Array, vec: number): number {
  let sum = 0;
  for (let i = 0; vec; vec >>>= 1, i++) if (vec & 1) sum ^= mat[i];
  return sum >>> 0;
}
function gf2Square(square: Uint32Array, mat: Uint32Array): void {
  for (let n = 0; n < 32; n++) square[n] = gf2Times(mat, mat[n]);
}
export function crc32Combine(crc1: number, crc2: number, len2: number): number {
  if (len2 <= 0) return crc1 >>> 0;
  const even = new Uint32Array(32);
  const odd = new Uint32Array(32);
  odd[0] = 0xedb88320;
  for (let n = 1, row = 1; n < 32; n++, row = (row << 1) >>> 0) odd[n] = row;
  gf2Square(even, odd);
  gf2Square(odd, even);
  // len2 can exceed 2^32, so halve it arithmetically - bit shifts would truncate it to 32 bits.
  do {
    gf2Square(even, odd);
    if (len2 % 2) crc1 = gf2Times(even, crc1);
    len2 = Math.floor(len2 / 2);
    if (!len2) break;
    gf2Square(odd, even);
    if (len2 % 2) crc1 = gf2Times(odd, crc1);
    len2 = Math.floor(len2 / 2);
  } while (len2);
  return (crc1 ^ crc2) >>> 0;
}

// ── Detection.xml - must stay character-identical to src/lib/intunewin.ts ────
const xmlEsc = (s: string): string =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function detectionXml(o: { appName: string; setupFile: string; unencSize: number; key: string; macKey: string; iv: string; mac: string; digest: string }): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<ApplicationInfo xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ToolVersion="1.8.6.0">
  <Name>${xmlEsc(o.appName)}</Name>
  <UnencryptedContentSize>${o.unencSize}</UnencryptedContentSize>
  <FileName>IntunePackage.intunewin</FileName>
  <SetupFile>${xmlEsc(o.setupFile)}</SetupFile>
  <EncryptionInfo>
    <EncryptionKey>${o.key}</EncryptionKey>
    <MacKey>${o.macKey}</MacKey>
    <InitializationVector>${o.iv}</InitializationVector>
    <Mac>${o.mac}</Mac>
    <ProfileIdentifier>ProfileVersion1</ProfileIdentifier>
    <FileDigest>${o.digest}</FileDigest>
    <FileDigestAlgorithm>SHA256</FileDigestAlgorithm>
  </EncryptionInfo>
</ApplicationInfo>`;
}

export interface PackageOptions {
  /** File name of the installer inside the package (Detection.xml's SetupFile). */
  setupFile: string;
  appName: string;
  /** Exact byte length of the installer about to be streamed. */
  size: number;
  /** CRC-32 of the installer, needed before the first byte (see the header comment). */
  crc32: number;
  /** Key material source - only overridden by the parity test, which needs fixed keys. */
  random?: (n: number) => Uint8Array;
}

/** Size of the finished package for an installer of `size` bytes - lets the caller check disk space first. */
export function packagedSize(setupFile: string, appName: string, size: number): number {
  return layout(setupFile, appName, size).total;
}

function layout(setupFile: string, appName: string, size: number) {
  const inner: ZipEntry = { name: Buffer.from(setupFile, 'utf8'), size, crc: 0, offset: 0 };
  const innerHead = localHeader(inner).length;
  const payloadSize = innerHead + size + zipTail([inner], innerHead + size).length;
  const ctSize = payloadSize - (payloadSize % 16) + 16;          // PKCS7 always adds 1..16 bytes
  const encSize = 32 + 16 + ctSize;
  const b64 = (n: number) => 'A'.repeat(Math.ceil(n / 3) * 4);
  const xmlSize = Buffer.byteLength(detectionXml({
    appName, setupFile, unencSize: payloadSize,
    key: b64(32), macKey: b64(32), iv: b64(16), mac: b64(32), digest: b64(32),
  }), 'utf8');
  const xml: ZipEntry = { name: Buffer.from(XML_ENTRY), size: xmlSize, crc: 0, offset: 0 };
  const enc: ZipEntry = { name: Buffer.from(ENC_ENTRY), size: encSize, crc: 0, offset: localHeader(xml).length + xmlSize };
  const encData = enc.offset + localHeader(enc).length;
  const centralStart = encData + encSize;
  return { inner, innerHead, payloadSize, ctSize, xml, enc, encData, centralStart,
           total: centralStart + zipTail([xml, enc], centralStart).length };
}

/**
 * Stream `source` (the raw installer bytes) into a finished .intunewin at `outPath`.
 * Rejects - leaving a partial file for the caller to delete - if the stream does not match the
 * declared size or CRC-32.
 */
export async function buildIntuneWinFile(source: AsyncIterable<Uint8Array>, outPath: string, o: PackageOptions): Promise<{ size: number }> {
  const rnd = o.random ?? randomBytes;
  const L = layout(o.setupFile, o.appName, o.size);
  L.inner.crc = o.crc32 >>> 0;

  const aesRaw = Buffer.from(rnd(32));
  const macRaw = Buffer.from(rnd(32));
  const iv = Buffer.from(rnd(16));

  const sha = createHash('sha256');                 // FileDigest: the UNENCRYPTED payload zip
  const hmac = createHmac('sha256', macRaw);        // over IV ‖ ciphertext
  const cipher = createCipheriv('aes-256-cbc', aesRaw, iv);

  const fh = await open(outPath, 'w');
  try {
    // Placeholders for everything that precedes the ciphertext; patched below.
    await fh.write(Buffer.alloc(L.encData + 32));
    await fh.write(iv);
    hmac.update(iv);
    let tailCrc = crc32(iv);                        // CRC of IV ‖ ciphertext (the HMAC is combined in later)
    let written = 0;
    const encrypt = async (plain: Uint8Array) => {
      sha.update(plain);
      const ct = cipher.update(plain);
      if (!ct.length) return;
      hmac.update(ct);
      tailCrc = crc32(ct, tailCrc);
      written += ct.length;
      await fh.write(ct);                           // awaiting here is what applies backpressure to the upload
    };

    await encrypt(localHeader(L.inner));
    let seen = 0;
    let seenCrc = 0;
    for await (const chunk of source) {
      seen += chunk.length;
      if (seen > o.size) throw new Error(`Upload is larger than the declared ${o.size} bytes.`);
      seenCrc = crc32(chunk, seenCrc);
      await encrypt(chunk);
    }
    if (seen !== o.size) throw new Error(`Upload ended after ${seen} of ${o.size} bytes.`);
    if (seenCrc !== L.inner.crc) throw new Error('Upload does not match its declared CRC-32.');
    await encrypt(zipTail([L.inner], L.innerHead + o.size));

    const last = cipher.final();
    hmac.update(last);
    tailCrc = crc32(last, tailCrc);
    written += last.length;
    await fh.write(last);
    if (written !== L.ctSize) throw new Error('Internal error: ciphertext size mismatch.');

    const mac = hmac.digest();
    const xml = Buffer.from(detectionXml({
      appName: o.appName, setupFile: o.setupFile, unencSize: L.payloadSize,
      key: aesRaw.toString('base64'), macKey: macRaw.toString('base64'), iv: iv.toString('base64'),
      mac: mac.toString('base64'), digest: sha.digest('base64'),
    }), 'utf8');
    if (xml.length !== L.xml.size) throw new Error('Internal error: Detection.xml size mismatch.');
    L.xml.crc = crc32(xml);
    L.enc.crc = crc32Combine(crc32(mac), tailCrc, 16 + L.ctSize);

    await fh.write(zipTail([L.xml, L.enc], L.centralStart));
    await fh.write(Buffer.concat([localHeader(L.xml), xml, localHeader(L.enc), mac]), { position: 0 });
    return { size: L.total };
  } finally {
    await fh.close();
  }
}
