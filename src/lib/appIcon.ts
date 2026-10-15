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
 * MSIs are not handled: their icons live in the Icon table's streams.
 */

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

/**
 * The installer's largest icon image: a PNG as stored, or a BMP-style image wrapped in a one-image
 * .ico. No DOM needed, so this part also runs under Node.
 */
export async function readIconImage(file: File): Promise<{ bytes: Uint8Array; type: 'image/png' | 'image/x-icon' } | null> {
  let r: Rsrc | null;
  try { r = await readRsrc(file); } catch { return null; }
  if (!r) return null;
  const group = await resource(r, RT_GROUP_ICON, null);
  if (!group || group.length < 6) return null;
  const gdv = new DataView(group.buffer, group.byteOffset, group.byteLength);
  const count = gdv.getUint16(4, true);

  // GRPICONDIRENTRY (14 bytes): width, height (0 = 256), colors, reserved, planes, bits, size, id.
  let best = -1, bestScore = -1;
  for (let i = 0; i < count; i++) {
    const at = 6 + i * 14;
    if (at + 14 > group.length) break;
    const w = group[at] || 256;
    const score = w * 100 + gdv.getUint16(at + 6, true);
    if (score > bestScore) { bestScore = score; best = at; }
  }
  if (best < 0) return null;
  const image = await resource(r, RT_ICON, gdv.getUint16(best + 12, true));
  if (!image) return null;
  if (isPng(image)) return { bytes: image, type: 'image/png' };

  // A BMP-style image: wrap it in a one-image .ico (the same 12 entry bytes, plus an offset) and let
  // the browser's icon decoder handle the AND mask and bit depths.
  const ico = new Uint8Array(6 + 16 + image.length);
  const idv = new DataView(ico.buffer);
  idv.setUint16(2, 1, true);
  idv.setUint16(4, 1, true);
  ico.set(group.subarray(best, best + 12), 6);
  idv.setUint32(6 + 8, image.length, true);
  idv.setUint32(6 + 12, 22, true);
  ico.set(image, 22);
  return { bytes: ico, type: 'image/x-icon' };
}

/** The installer's own icon as a PNG, or null when it has none we can read. */
export async function extractAppIcon(file: File): Promise<Blob | null> {
  const img = await readIconImage(file);
  if (!img) return null;
  return img.type === 'image/png' ? new Blob([img.bytes as BlobPart], { type: 'image/png' }) : toPng(img.bytes, img.type);
}
