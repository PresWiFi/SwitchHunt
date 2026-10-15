/**
 * The raw bytes of an MSI's product icon, for the Intune app logo.
 *
 * An MSI keeps each icon as a stream named "Icon.<Name>" in the root storage. ARPPRODUCTICON names
 * the one Programs and Features shows; without it, the largest icon stream is the best guess (the
 * small ones tend to be shortcut and folder glyphs). The stream is a .ico file - or, now and then,
 * an EXE/DLL carrying the icon in its resources - and appIcon.ts turns it into a PNG.
 *
 * Deliberately NOT built on msi.ts. That file is shared byte-for-byte with upstream's other repos
 * (scripts/check-lib-parity.mjs), so this fork keeps its own small compound-file reader rather than
 * drift from it. This one also reads from the File in slices - the header, the FAT, the directory and
 * the one stream - instead of the whole MSI, so it works on an MSI of any size.
 */

const ENDOFCHAIN = 0xfffffffe;
const FREESECT = 0xffffffff;
const NOSTREAM = 0xffffffff;
const CFB_SIG = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const MAX_ICON = 4 * 1024 * 1024;
const B64 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._';

export const isCompoundFile = (head: Uint8Array): boolean => CFB_SIG.every((v, i) => head[i] === v);

/** MSI stream names pack two base64 characters into one code point; table streams carry a 0x4840 marker. */
function decodeStreamName(raw: string): string {
  let out = '';
  for (let i = 0; i < raw.length; i++) {
    const cp = raw.charCodeAt(i);
    if (cp === 0x4840 && i === 0) continue;
    if (cp >= 0x3800 && cp < 0x4800) out += B64[(cp - 0x3800) & 0x3f] + B64[((cp - 0x3800) >> 6) & 0x3f];
    else if (cp >= 0x4800 && cp < 0x4840) out += B64[cp - 0x4800];
    else out += String.fromCharCode(cp);
  }
  return out;
}

const u32s = (b: Uint8Array): Uint32Array => {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const out = new Uint32Array(b.length >> 2);
  for (let i = 0; i < out.length; i++) out[i] = dv.getUint32(i * 4, true);
  return out;
};

export async function readMsiIconStream(file: File, preferred?: string): Promise<Uint8Array | null> {
  const header = new Uint8Array(await file.slice(0, 512).arrayBuffer());
  if (header.length < 512 || !isCompoundFile(header)) return null;
  const hv = new DataView(header.buffer);
  const sectorSize = 1 << hv.getUint16(0x1e, true);
  const miniSectorSize = 1 << hv.getUint16(0x20, true);
  const numFatSectors = hv.getUint32(0x2c, true);
  const dirStart = hv.getUint32(0x30, true);
  const miniCutoff = hv.getUint32(0x38, true);
  const miniFatStart = hv.getUint32(0x3c, true);
  const numDifat = hv.getUint32(0x48, true);
  const perSector = sectorSize / 4;
  const sectorOff = (n: number) => (n + 1) * sectorSize;   // the header fills sector "-1"

  // Read a list of sectors, one slice per run of consecutive ones (FATs and streams are mostly contiguous).
  const readSectors = async (secs: number[]): Promise<Uint8Array> => {
    const out = new Uint8Array(secs.length * sectorSize);
    for (let k = 0; k < secs.length;) {
      let run = 1;
      while (k + run < secs.length && secs[k + run] === secs[k] + run) run++;
      const off = sectorOff(secs[k]);
      if (off + run * sectorSize > file.size + sectorSize) throw new Error('sector out of bounds');
      out.set(new Uint8Array(await file.slice(off, off + run * sectorSize).arrayBuffer()), k * sectorSize);
      k += run;
    }
    return out;
  };

  // DIFAT -> FAT sector numbers: 109 in the header, then a chain of DIFAT sectors.
  const fatSectors: number[] = [];
  for (let i = 0; i < 109 && fatSectors.length < numFatSectors; i++) {
    const s = hv.getUint32(0x4c + i * 4, true);
    if (s !== FREESECT && s !== ENDOFCHAIN) fatSectors.push(s);
  }
  for (let d = hv.getUint32(0x44, true), g = 0; numDifat > 0 && d !== ENDOFCHAIN && d !== FREESECT && g++ < numDifat + 4;) {
    const v = u32s(await readSectors([d]));
    for (let i = 0; i < perSector - 1 && fatSectors.length < numFatSectors; i++) {
      if (v[i] !== FREESECT && v[i] !== ENDOFCHAIN) fatSectors.push(v[i]);
    }
    d = v[perSector - 1];
  }
  const fat = u32s(await readSectors(fatSectors));
  const chain = (start: number, table: Uint32Array): number[] => {
    const out: number[] = [];
    for (let s = start, g = 0; s !== ENDOFCHAIN && s !== FREESECT && s < table.length && g++ <= table.length; s = table[s]) out.push(s);
    return out;
  };

  // Directory: walk only the root storage's own children - names are unique per storage, and
  // a multi-language MSI's transforms carry streams of their own (see msi.ts).
  const dir = await readSectors(chain(dirStart, fat));
  const dv = new DataView(dir.buffer);
  const entry = (i: number) => {
    const b = i * 128;
    let name = '';
    const chars = Math.max(0, (dv.getUint16(b + 0x40, true) >> 1) - 1);
    for (let c = 0; c < chars; c++) name += String.fromCharCode(dv.getUint16(b + c * 2, true));
    return {
      name, type: dir[b + 0x42], left: dv.getUint32(b + 0x44, true), right: dv.getUint32(b + 0x48, true),
      child: dv.getUint32(b + 0x4c, true), start: dv.getUint32(b + 0x74, true), size: dv.getUint32(b + 0x78, true),
    };
  };
  const count = dir.length / 128;
  let rootIdx = -1;
  for (let i = 0; i < count; i++) if (dir[i * 128 + 0x42] === 5) { rootIdx = i; break; }
  if (rootIdx < 0) return null;
  const root = entry(rootIdx);
  const icons = new Map<string, ReturnType<typeof entry>>();
  const seen = new Set<number>();
  const stack = root.child === NOSTREAM ? [] : [root.child];
  while (stack.length) {
    const i = stack.pop()!;
    if (i === NOSTREAM || i >= count || seen.has(i)) continue;
    seen.add(i);
    const e = entry(i);
    stack.push(e.left, e.right);
    const name = decodeStreamName(e.name);
    if (e.type === 2 && name.startsWith('Icon.')) icons.set(name.slice(5), e);
  }

  const pick = (preferred && icons.get(preferred))
    || [...icons.values()].sort((a, b) => b.size - a.size)[0];
  if (!pick || pick.size <= 0 || pick.size > MAX_ICON) return null;
  if (pick.size >= miniCutoff) return (await readSectors(chain(pick.start, fat))).subarray(0, pick.size);

  // Small streams live in the mini stream (the root entry's own stream), in 64-byte mini sectors.
  const miniFat = u32s(await readSectors(chain(miniFatStart, fat)));
  const ministream = await readSectors(chain(root.start, fat));
  const out = new Uint8Array(pick.size);
  let written = 0;
  for (const s of chain(pick.start, miniFat)) {
    const take = Math.min(miniSectorSize, pick.size - written);
    out.set(ministream.subarray(s * miniSectorSize, s * miniSectorSize + take), written);
    written += take;
    if (written >= pick.size) break;
  }
  return out;
}
