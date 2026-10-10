// @ts-check
import { defineConfig } from 'astro/config';

// Static build - no Astro adapter. The output in `dist/` is plain static files and still works
// on any static host (GitHub Pages, Cloudflare Pages, Netlify, `npx serve dist`), where packaging
// falls back to the in-browser builder. server/main.ts serves the same `dist/` and adds the
// on-disk .intunewin packager for installers too big for a browser tab.
export default defineConfig({
  site: 'https://getrff.com',
  // Relative asset paths (`./_astro/...`) rather than absolute (`/_astro/...`). The build is
  // published as a downloadable zip whose whole promise is "serve it anywhere", and absolute paths
  // break that the moment it is not the server root - silently, because the HTML still loads and
  // only the CSS and JS 404. Verified by verify-tool-release.mjs on every release.
  build: { assetsPrefix: '.' },
});
