/**
 * The application's icon, pulled out of an EXE installer for the Intune app logo.
 *
 * Walks the PE resource tree for the first RT_GROUP_ICON (the one Explorer shows), picks its
 * largest, deepest image, and returns it as a PNG. Modern icons store their 256 px image as a PNG
 * already; older BMP-style images are wrapped in a one-image .ico and decoded by the browser.
 *
 * Only the PE headers, the resource directories and the chosen icon are read from the File - each
 * with its own small slice - so a multi-GB installer costs no more than a small one, wherever in
 * the file its icon sits. (Docker Desktop's .rsrc section is 620 MB: the whole payload is a resource.)
 * MSIs: the product icon stream is found by msiIcon.ts and decoded here like any other .ico/EXE.
 */
import { isCompoundFile, readMsiIconStream } from './msiIcon';

const RT_ICON = 3;
const RT_GROUP_ICON = 14;
const MAX_ICON = 4 * 1024 * 1024;
const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

/** The .rsrc section, read on demand: `read(off, len)` is relative to the section's start. */
interface Rsrc { read(off: number, len: number): Promise<Uint8Array>; size: number; va: number; }

const view = (b: Uint8Array) => new DataView(b.buffer, b.byteOffset, b.byteLength);

/** The .rsrc section of a PE file, or null if it has none (or is not a PE). */
async function readRsrc(file: File): Promise<Rsrc | null> {
  const head = new Uint8Array(await file.slice(0, 64 * 1024).arrayBuffer());
  if (head.length < 0x40 || head[0] !== 0x4d || head[1] !== 0x5a) return null; // MZ
  const dv = view(head);
  const peOff = dv.getUint32(0x3c, true);
  if (peOff + 24 > head.length || dv.getUint32(peOff, true) !== 0x00004550) return null; // 'PE\0\0'
  const numSections = dv.getUint16(peOff + 6, true);
  const secStart = peOff + 24 + dv.getUint16(peOff + 20, true);
  for (let i = 0; i < numSections; i++) {
    const so = secStart + i * 40;
    if (so + 40 > head.length) break;
    let name = '';
    for (let k = 0; k < 8 && head[so + k]; k++) name += String.fromCharCode(head[so + k]);
    if (name !== '.rsrc') continue;
    const va = dv.getUint32(so + 12, true);
    const ptr = dv.getUint32(so + 20, true);
    const size = Math.min(dv.getUint32(so + 16, true), file.size - ptr);
    if (!ptr || size <= 0) return null;
    return {
      size, va,
      read: async (off, len) => new Uint8Array(await file.slice(ptr + off, ptr + Math.min(off + len, size)).arrayBuffer()),
    };
  }
  return null;
}

/** Entries of a resource directory at `off` (relative to the section): id (-1 for named) + target. */
async function dirEntries(r: Rsrc, off: number): Promise<Array<{ id: number; off: number; isDir: boolean }>> {
  const hdr = await r.read(off, 16);
  if (hdr.length < 16) return [];
  const n = view(hdr).getUint16(12, true) + view(hdr).getUint16(14, true);
  const body = await r.read(off + 16, Math.min(n, 4096) * 8);
  const dv = view(body);
  const out = [];
  for (let eo = 0; eo + 8 <= body.length; eo += 8) {
    const nameField = dv.getUint32(eo, true);
    const target = dv.getUint32(eo + 4, true);
    out.push({ id: nameField & 0x80000000 ? -1 : nameField, off: target & 0x7fffffff, isDir: (target & 0x80000000) !== 0 });
  }
  return out;
}

/** The data of a resource: type -> name (`id`, or the first when null) -> first language. */
async function resource(r: Rsrc, type: number, id: number | null): Promise<Uint8Array | null> {
  const t = (await dirEntries(r, 0)).find((e) => e.id === type && e.isDir);
  if (!t) return null;
  const names = await dirEntries(r, t.off);
  const n = id === null ? names[0] : names.find((e) => e.id === id);
  if (!n?.isDir) return null;
  const leaf = (await dirEntries(r, n.off))[0];
  if (!leaf || leaf.isDir) return null;
  const entry = await r.read(leaf.off, 8);
  if (entry.length < 8) return null;
  const start = view(entry).getUint32(0, true) - r.va;   // RVA -> offset within the section
  const size = view(entry).getUint32(4, true);
  if (start < 0 || size <= 0 || size > MAX_ICON || start + size > r.size) return null;
  return r.read(start, size);
}

const isPng = (b: Uint8Array) => PNG_SIG.every((v, i) => b[i] === v);

/** Decode an image the browser understands (here: a one-image .ico) and re-encode it as PNG. */
async function toPng(data: Uint8Array, type: string): Promise<Blob | null> {
  const url = URL.createObjectURL(new Blob([data as BlobPart], { type }));
  try {
    const img = new Image();
    img.src = url;
    await img.decode();
    if (!img.naturalWidth) return null;
    const canvas = document.createElement('canvas');
    canvas.width = img.naturalWidth; canvas.height = img.naturalHeight;
    canvas.getContext('2d')!.drawImage(img, 0, 0);
    return await new Promise((resolve) => canvas.toBlob(resolve, 'image/png'));
  } catch {
    return null;
  } finally {
    URL.revokeObjectURL(url);
  }
}

type IconImage = { bytes: Uint8Array; type: 'image/png' | 'image/x-icon' };

/** Index of the largest, deepest image in an icon directory (ICONDIR or GRPICONDIR), or -1. */
function largest(dir: Uint8Array, entrySize: 14 | 16): number {
  const dv = view(dir);
  if (dir.length < 6) return -1;
  let best = -1, bestScore = -1;
  for (let i = 0; i < dv.getUint16(4, true); i++) {
    const at = 6 + i * entrySize;
    if (at + entrySize > dir.length) break;
    const score = (dir[at] || 256) * 100 + dv.getUint16(at + 6, true);   // width (0 = 256), then bit depth
    if (score > bestScore) { bestScore = score; best = at; }
  }
  return best;
}

/**
 * One icon image, ready to use: a PNG as stored, or a BMP-style image wrapped in a one-image .ico
 * (its 12 directory-entry bytes, plus an offset) for the browser's icon decoder.
 */
function iconImage(entry: Uint8Array, image: Uint8Array): IconImage {
  if (isPng(image)) return { bytes: image, type: 'image/png' };
  const ico = new Uint8Array(6 + 16 + image.length);
  const idv = view(ico);
  idv.setUint16(2, 1, true);
  idv.setUint16(4, 1, true);
  ico.set(entry.subarray(0, 12), 6);
  idv.setUint32(6 + 8, image.length, true);
  idv.setUint32(6 + 12, 22, true);
  ico.set(image, 22);
  return { bytes: ico, type: 'image/x-icon' };
}

/** The largest image of an .ico file. */
function fromIco(ico: Uint8Array): IconImage | null {
  const best = largest(ico, 16);
  if (best < 0) return null;
  const size = view(ico).getUint32(best + 8, true), off = view(ico).getUint32(best + 12, true);
  if (!size || off + size > ico.length) return null;
  return iconImage(ico.subarray(best, best + 12), ico.subarray(off, off + size));
}

/** The largest image of a PE file's first icon group (the one Explorer shows). */
async function fromPe(file: File): Promise<IconImage | null> {
  let r: Rsrc | null;
  try { r = await readRsrc(file); } catch { return null; }
  if (!r) return null;
  const group = await resource(r, RT_GROUP_ICON, null);
  if (!group) return null;
  const best = largest(group, 14);
  if (best < 0) return null;
  const image = await resource(r, RT_ICON, view(group).getUint16(best + 12, true));   // GRPICONDIRENTRY id
  return image ? iconImage(group.subarray(best, best + 12), image) : null;
}

/**
 * The installer's largest icon image: an EXE's own icon, or an MSI's product icon (`msiIcon` is its
 * ARPPRODUCTICON, when known). No DOM needed, so this part also runs under Node.
 */
export async function readIconImage(file: File, msiIcon?: string): Promise<IconImage | null> {
  const head = new Uint8Array(await file.slice(0, 8).arrayBuffer());
  if (!isCompoundFile(head)) return fromPe(file);
  let data: Uint8Array | null;
  try { data = await readMsiIconStream(file, msiIcon); } catch { return null; }
  if (!data || data.length < 6) return null;
  if (data[0] === 0x4d && data[1] === 0x5a) return fromPe(new File([data as BlobPart], 'icon.exe'));   // icon kept in an EXE/DLL
  if (view(data).getUint32(0, true) === 0x00010000) return fromIco(data);                               // ICONDIR, type 1
  return isPng(data) ? { bytes: data, type: 'image/png' } : null;
}

/** The installer's own icon as a PNG, or null when it has none we can read. */
export async function extractAppIcon(file: File, msiIcon?: string): Promise<Blob | null> {
  const img = await readIconImage(file, msiIcon);
  if (!img) return null;
  return img.type === 'image/png' ? new Blob([img.bytes as BlobPart], { type: 'image/png' }) : toPng(img.bytes, img.type);
}
