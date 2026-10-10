# SwitchHunt

**Drop a Windows installer in your browser → get its silent-install switches.** No signup, no agent. The file you drop is analyzed **entirely in your browser**.

> **This is a fork of [deadarcher/SwitchHunt](https://github.com/deadarcher/SwitchHunt)** that removes the 512 MB limit on `.intunewin` packaging. Upstream builds the package inside the browser tab, which needs 4-5x the installer's size in RAM. This fork ships a small server: the browser is only the front end, the installer is streamed to the server and zipped + encrypted **straight to disk**, and the finished package comes back as a normal download. Memory stays flat (~100 MB on the server, a few tens of MB in the tab) whatever the size - a 5 GB installer packages in under 20 seconds on an SSD. See [Server packaging](#server-packaging-no-size-limit).
>
> The original hosted, 100% client-side tool lives at https://getrff.com/switchhunt/.

Works on ~85% of installers out of the box, plus a curated catalog for the painful vendor one-offs.

---

## What it does

Drop an `.exe` or `.msi` and SwitchHunt identifies the installer engine from its bytes, then hands you:

- **The full command set** - install / repair / uninstall / extract, not just a single silent flag - with the modifier switches for each.
- **CMD ⇄ PowerShell** toggle (rewrites `.\`, the `&` call operator, `$env:` paths) and an **interactive command builder** (operation, UI level, INSTALLDIR, properties).
- **Deep MSI analysis** - a from-scratch in-browser MS-CFB (compound-file) reader decodes the `Property`, `Control`, `LaunchCondition` and `CustomAction` tables to surface a tiered "**properties you probably need to set**" list (required / likely / sensitive / optional), a full property dump, and an **uninstall-replay** warning (MSI properties are transaction-scoped, so secrets set at install must be passed again at `/x`).
- **Package for deployment:**
  - a **PSAppDeployToolkit v4** wrapper (`Invoke-AppDeployToolkit.ps1`) with the right `Start-ADTMsiProcess` / `Start-ADTProcess` calls, plus DeployMode / suppress-reboot / Terminal-Server options;
  - a real **`.intunewin`** (STORE zip + AES-256-CBC + HMAC-SHA256 + `Detection.xml`, exactly like `IntuneWinAppUtil.exe`) - uploadable straight to Intune, no toolchain to install. Built on the server with no size limit, or in the browser (up to 512 MB) when there is no server.

### Engines detected

MSI · WiX Burn · Advanced Installer · Inno Setup · NSIS · InstallShield · InstallAware · BitRock InstallBuilder · Wise · MSIX/AppX · Squirrel · 7-Zip/WinRAR self-extractors - with a best-effort switch *harvest* for the packed/custom long tail.

### The catalog (the weird stuff)

Signature detection can't derive a custom CLI's flags (Citrix, Teams machine-wide, AnyDesk, Docker Desktop, CrowdStrike, GlobalProtect…). Those live in [`src/lib/catalog.ts`](src/lib/catalog.ts) as **hand-verified known strings**, clearly labeled in the UI as "from catalog, not read from your file." For well-known apps the catalog also carries the real **uninstall** command and a **detection** path (the install dir an EXE installer never records).

- **Browse the catalog:** [CATALOG.md](CATALOG.md) (readable table) - or the machine-readable [`catalog/catalog.json`](catalog/catalog.json).
- **Add one - no coding:** [open a submission issue](https://github.com/deadarcher/SwitchHunt/issues/new?template=silent-install-string.yml) (a quick form), or PR `src/lib/catalog.ts` ([CONTRIBUTING](CONTRIBUTING.md)).

This is where the project most needs help. `CATALOG.md` + `catalog/catalog.json` are generated from the `.ts` - run `npm run gen:catalog`, don't hand-edit them.

---

## Why is analysis client-side?

Feeding a community-sourced "install command" into a tool that runs it as SYSTEM across a fleet is a supply-chain attack surface. SwitchHunt deliberately **does not run anything** - it only reads bytes and looks up strings. Detection, MSI parsing and command building all happen in the page; dropping a file sends nothing anywhere.

The one thing that leaves the browser is the installer **when you click "Build .intunewin (on server)"** - and it goes only to the SwitchHunt server you are running, never to a third party. The page says so when a server is present.

## Run it

### Docker (the full thing: site + server packaging)

A prebuilt multi-arch image is published to GHCR on every push to `main`:

```bash
docker run -d --name switchhunt -p 4321:8080 -v switchhunt-data:/data ghcr.io/preswifi/switchhunt
```

Then open http://localhost:4321. Or build it yourself from a clone:

```bash
docker compose up -d --build   # http://localhost:4321
```

| Variable | Default | What it does |
| --- | --- | --- |
| `MAX_UPLOAD_GB` | `30` | Largest installer accepted. 30 GB is Intune's own Win32 app limit; `0` = no limit. |
| `PACKAGE_TTL_MINUTES` | `60` | How long a built package waits to be downloaded before it is deleted. |
| `DATA_DIR` | `/data` | Where packages are written while in flight. Mount a volume with room for your largest installer. |
| `PORT` | `8080` | Port the server listens on inside the container. |

**There is no authentication.** Anyone who can reach the port can upload files to the server's disk (up to `MAX_UPLOAD_GB` each, refused when the disk is full). Run it on a network you trust, or put it behind a reverse proxy that adds auth - and if you do, raise the proxy's body-size limit and turn off request buffering (nginx: `client_max_body_size 0; proxy_request_buffering off;`), or the proxy becomes the new size limit.

Thanks to [timwelchnz](https://www.reddit.com/user/timwelchnz/) for suggesting the Docker install option upstream.

### Without Docker

Needs Node 24+ (the server is dependency-free TypeScript that Node runs directly):

```bash
npm install
npm run build    # static site -> dist/
npm start        # http://localhost:8080 - serves dist/ and the packaging API
```

### Static only (no server)

`dist/` is still plain static files and still works on GitHub Pages, Cloudflare Pages, Netlify, or `npx serve dist`. With no server behind it the page falls back to building the `.intunewin` in the browser, with upstream's 512 MB cap. `npm run dev` behaves the same way.

## Server packaging (no size limit)

1. **Checksum** - the browser streams the file once to compute its CRC-32. (A zip header that gets encrypted *before* the installer bytes needs it, so it has to be known up front.)
2. **Upload + encrypt** - the browser streams the file from disk as the request body. The server wraps it in a STORE zip, SHA-256 hashes it, AES-256-CBC encrypts it and HMACs the ciphertext chunk by chunk, writing directly to a file in `DATA_DIR`. The HMAC and `Detection.xml` sit *ahead* of the ciphertext in the format, so they are written as placeholders and patched in at the end. Past 4 GB both zips switch to ZIP64.
3. **Download** - the page triggers an ordinary browser download. The package is deleted from the server as soon as the download completes (or after `PACKAGE_TTL_MINUTES` if it never does).

The upload is verified against the declared size and CRC-32, and a mismatch is rejected. Keys are generated per package with `crypto.randomBytes` and exist only inside the package's own `Detection.xml`, as the format requires.

```
GET  api/health                             -> { ok, maxBytes }
POST api/intunewin?file=&app=&crc32=<hex>   body: raw installer, Content-Type: application/octet-stream
GET  api/intunewin/<id>                     -> the package
```

`npm run test:server` checks that the server's output is **byte-identical** to the in-browser builder's for the same keys, and round-trips a package through the HTTP API. `node scripts/test-server-package.ts --big 5 out.intunewin` adds a 5 GB ZIP64 package. Not yet tested: uploading a >4 GB (ZIP64) package to a live Intune tenant - packages that size from `IntuneWinAppUtil.exe` are ZIP64 too, but verify one in your tenant before relying on it.

## How it works (short version)

- **Engine detection** (`src/lib/installerDetect.ts`): byte signatures + PE version-resource parsing for metadata. `.NET` requires the `_CorExeMain` stub (not just an `mscoree.dll` string) to avoid false positives, etc.
- **MSI parsing** (`src/lib/msi.ts`): a hand-rolled MS-CFB reader (the `cfb` npm package chokes on the 4096-byte-sector MSIs large enterprise packages use) that decodes the table streams.
- **Packaging** (`src/lib/psadt.ts`, `src/lib/intunewin.ts`): pure string-templating + WebCrypto. No native deps.
- **Server packaging** (`server/intunewin.ts`, `server/main.ts`, `src/lib/serverPackager.ts`): the same format as `intunewin.ts`, streamed with `node:crypto` to disk. No npm dependencies.

## License

MIT - see [LICENSE](LICENSE).

SwitchHunt is built by [RFF](https://getrff.com) - Really Freakin' Fast Windows endpoint deployment. Server packaging added in this fork.
