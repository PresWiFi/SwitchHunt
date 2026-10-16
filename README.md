# SwitchHunt

## Workflow: installer to Intune app

**One-time setup** - run the server (any machine with Docker):

```bash
docker run -d --name switchhunt --restart unless-stopped -p 4321:8080 -v switchhunt-data:/data ghcr.io/preswifi/switchhunt
```

To update later: `docker pull ghcr.io/preswifi/switchhunt`, `docker rm -f switchhunt`, then the `docker run` line again.

**Per app**

1. Open http://localhost:4321 and drop the installer on the page. It identifies the installer type and shows the silent install and uninstall commands.
2. Scroll to **Build a .intunewin**. Check the **Install** and **Uninstall** boxes and fix them if needed - especially the uninstall box for EXE installers, which often contains a `<placeholder>`.
3. Check the **Logo** preview - it is the installer's own icon. For an MSI it is the product icon from Programs and Features. If it is a generic setup icon, or there is none, click **Choose image…** and pick the app's logo.
4. Optional: a **Post-install** step - PowerShell that runs as SYSTEM after a successful install (Docker Desktop's adds the signed-in user to `docker-users`).
5. Pick the **Detection** rule (MSI code / File / Registry) and check the value below it: the file the app installs, or its name as it appears under Programs and Features. Without a catalog entry these are guesses - step 8 replaces them with the real ones.
6. Click **Build deployment bundle (.zip)**. It checksums, uploads, and downloads `<installer>-Intune.zip`. The server opens the package the way Intune would before handing it over (decrypts it, checks the HMAC, SHA-256 and every file's CRC-32) - the status line says so. The settings are saved for this app, so the next version's installer starts from them (**Saved** row; **Forget** clears them).
7. Unzip it and open `README.txt`, which lists exactly what to enter in the portal.
8. **Test it**: double-click `Test-InSandbox.cmd`. A fresh Windows Sandbox opens and runs the package as Intune would, as SYSTEM - detect, install, detect, uninstall, detect - and writes a pass/fail report to `SandboxResults\<date-time>\`. It also records what the install really registered (display name, version, program file, uninstall command): click **Load sandbox results…** on the page, pick that `report.json`, and build the bundle again. Needs Windows Pro/Enterprise with the Windows Sandbox feature on; apps that need virtualization themselves (Docker Desktop, WSL) cannot run inside it.

**In Intune** (Apps > Windows > Add > Windows app (Win32))

1. Upload the `.intunewin` from the zip. Under App information, upload `Logo.png` as the logo.
2. Install command: `powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File .\Install.ps1`
3. Uninstall command: `powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File .\Uninstall.ps1`
4. Install behavior: System.
5. Detection rules: use a custom detection script, upload `Detect.ps1`, with "Run script as 32-bit process" and "Enforce script signature check" both set to No.
6. Assign it to a test device first.

**Checking a package** - drop any `.intunewin` on the page (ours, or one from IntuneWinAppUtil.exe) and the server opens it the way Intune would: it shows whether it decrypts and is intact, the files inside, and the text of its scripts.

**Troubleshooting on a device** - look in `C:\Intune\Logs` for `<App>_<Version>-Install.log`, `-Uninstall.log` and `-Detect.log` (plus `-Install-msi.log` for MSI installers).

If a command turns out to be wrong, fix it in the box on the page and build the bundle again. Editing the loose `Install.ps1` in the zip does nothing, because Intune runs the copy inside the `.intunewin`.

The **Build .intunewin (on server)** button is still there if you only want the bare package and plan to enter the raw commands yourself.

---

## About

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
  - a **deployment bundle** (server only): one zip with the `.intunewin` - `Install.ps1` and `Uninstall.ps1` packaged inside it - plus a `Detect.ps1` for Intune's custom detection script, the app's icon as `Logo.png`, and a README listing the exact portal settings. The scripts log to `C:\Intune\Logs` on the device. See [Deployment bundle](#deployment-bundle);
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

### Deployment bundle

**Build deployment bundle (.zip)** produces `<installer>-Intune.zip`:

| File | Use |
| --- | --- |
| `<installer>.intunewin` | The app package. Contains the installer, `Install.ps1` and `Uninstall.ps1`. |
| `Detect.ps1` | Upload as the custom detection script. |
| `Install.ps1`, `Uninstall.ps1` | Reference copies of the two scripts inside the package. |
| `Logo.png` | The app's icon, for the logo under App information (when one was found or chosen). |
| `Test-InSandbox.cmd`, `Test-InSandbox.ps1` | The Windows Sandbox test - see below. |
| `README.txt` | The install / uninstall commands, detection, requirement and return-code settings to enter in Intune, and anything to fix first. |

- **Install / Uninstall** run the command shown in the two boxes above the button (prefilled from detection or the catalog; edit them if a command has a `<placeholder>` or no uninstall command was found). They relaunch as 64-bit PowerShell, return the installer's own exit code to Intune, write a transcript to `C:\Intune\Logs\<App>_<Version>-Install.log` / `-Uninstall.log`, and add a verbose `/L*v` log for MSI. They refuse to run a command that still contains a `<placeholder>`.
- **Post-install**, when one is entered, runs inside `Install.ps1` after a success exit code (0, 1707, 3010, 1641). If it throws, `Install.ps1` returns 1. Every script is started with `-NonInteractive`, so anything that would wait for input fails with an error in the log instead of hanging the deployment forever.
- **Detect** follows the detection rule picked on the page: a file path when the catalog knows one, the MSI product code when there is one, otherwise the app's display name in "Programs and Features" (a guess from the installer's metadata - check it). Each check adds a line to `C:\Intune\Logs\<App>_<Version>-Detect.log`.

**Sandbox test.** `Test-InSandbox.ps1` writes a `.wsb` that maps the unzipped bundle into a fresh Windows Sandbox and runs itself in there. Inside, it unpacks the `.intunewin` with the keys from `Detection.xml` (HMAC checked, AES decrypted - as the Intune agent does), then runs each step as SYSTEM through a scheduled task, with Install/Uninstall started from 32-bit PowerShell like the agent: `Detect` (expect not installed), `Install`, `Detect` (expect installed), `Uninstall`, `Detect` (expect not installed). Each step has a time limit (60 minutes for install and uninstall, as in Intune), so a silent install stuck on a dialog shows up as a failure. It compares the uninstall registry before and after the install to record what the app really registered; the page's **Load sandbox results…** reads that `report.json`.

**Saved settings.** After each bundle, the page saves what it was built with - commands (with the installer's file name as `{file}`), detection, post-install and a custom logo - under `DATA_DIR/profiles/<app>.json`. The next installer of the same app loads them; a minimum version that equalled the old version moves up to the new one.

The scripts are generated in the page (`src/lib/deployScripts.ts`) and sent with the upload; the server only zips them. The bundle zip is never written to disk - the server keeps the package and wraps it on the way out - so a bundle needs no more space than a plain package.

```
GET  api/health                             -> { ok, maxBytes }
POST api/intunewin?file=&app=&crc32=<hex>   body: raw installer, Content-Type: application/octet-stream
POST api/bundle                             body: [u32 LE length][JSON incl. scripts][raw installer]
GET  api/intunewin/<id>                     -> the package (checked by the server before this is offered)
POST api/inspect                            body: a .intunewin -> { ok, problems, passed, files, scripts }
GET  api/profiles                           -> saved app settings, listed
GET|PUT|DELETE api/profiles/<key>           one app's saved settings (PUT as application/json)
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
