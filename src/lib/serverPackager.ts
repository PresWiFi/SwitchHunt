/**
 * Browser side of server packaging (see server/main.ts).
 *
 * When the page is served by the SwitchHunt server, the .intunewin is built THERE: the installer is
 * streamed up from disk, encrypted to a file on the server, and comes back as an ordinary download.
 * The tab never holds the file - not the read buffer, not the zip, not the ciphertext - so the
 * 512 MB in-browser ceiling does not apply. On a plain static host probeServer() returns null and
 * the page falls back to the in-browser builder.
 */

export interface ServerInfo {
  /** Largest installer the server accepts, in bytes. 0 = no limit. */
  maxBytes: number;
}

export type PackagePhase = 'checksum' | 'upload' | 'finish';

/** Is there a packaging server behind this page? Relative URL, so it works under a sub-path too. */
export async function probeServer(): Promise<ServerInfo | null> {
  try {
    const res = await fetch('api/health', { cache: 'no-store' });
    if (!res.ok) return null;
    const body = await res.json();
    return body?.ok === true ? { maxBytes: Number(body.maxBytes) || 0 } : null;
  } catch {
    return null;
  }
}

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

/**
 * CRC-32 of a file, read as a stream so only one chunk is in memory at a time.
 *
 * The server needs this BEFORE the upload: the checksum sits in a zip header that is encrypted ahead
 * of the installer bytes, so it cannot be filled in afterwards. The server re-computes it over what
 * actually arrives and rejects a mismatch.
 */
async function crc32OfFile(file: File, onProgress: (fraction: number) => void): Promise<number> {
  const reader = file.stream().getReader();
  let c = 0xffffffff;
  let done = 0;
  for (;;) {
    const { value, done: end } = await reader.read();
    if (end) break;
    for (let i = 0; i < value.length; i++) c = CRC_TABLE[(c ^ value[i]) & 0xff] ^ (c >>> 8);
    done += value.length;
    onProgress(done / file.size);
  }
  return (c ^ 0xffffffff) >>> 0;
}

/** Scripts for a deployment bundle: see generateDeployScripts() and the server's api/bundle. */
export interface BundleFiles {
  payloadFiles: Array<{ name: string; text: string }>;
  bundleFiles: Array<{ name: string; text: string }>;
}

/**
 * Build a .intunewin on the server - or, given `bundle`, a zip of the .intunewin (with the payload
 * scripts packaged inside it) plus the loose bundle files. Resolves with the download URL once it is ready.
 * XMLHttpRequest rather than fetch: it streams a File body from disk just the same, and it is the
 * only one of the two that reports upload progress.
 */
export async function packageOnServer(
  file: File, setupFile: string, appName: string,
  onProgress: (phase: PackagePhase, fraction: number) => void,
  bundle?: BundleFiles,
): Promise<{ url: string; fileName: string }> {
  const crc = await crc32OfFile(file, (f) => onProgress('checksum', f));
  const meta = { file: setupFile, app: appName, crc32: crc.toString(16) };
  let url = `api/intunewin?${new URLSearchParams(meta)}`;
  let body: Blob = file;
  if (bundle) {
    // One request: [u32 LE length][JSON][installer]. A Blob made of a Blob is still streamed from
    // disk by the browser, so the installer is not read into memory to build this.
    const json = new TextEncoder().encode(JSON.stringify({ ...meta, ...bundle }));
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, json.length, true);
    url = 'api/bundle';
    body = new Blob([len, json, file]);
  }

  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', url);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.responseType = 'json';
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress('upload', e.loaded / e.total); };
    xhr.upload.onload = () => onProgress('finish', 1);
    xhr.onload = () => {
      const body = xhr.response as { url?: string; fileName?: string; error?: string } | null;
      if (xhr.status === 201 && body?.url && body.fileName) resolve({ url: body.url, fileName: body.fileName });
      else reject(new Error(body?.error ?? `the server answered ${xhr.status}`));
    };
    xhr.onerror = () => reject(new Error('the upload was interrupted'));
    xhr.send(body);
  });
}
