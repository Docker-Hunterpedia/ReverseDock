import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The dashboard is embedded in the rdock binary and served by the admin listener
// (ADR-0024). `pnpm dev` proxies the API to a local rdock on 127.0.0.1:2080.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    // No inline scripts: the admin CSP is `script-src 'self'`.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    sourcemap: false,
  },
  server: {
    proxy: { "/api": { target: "http://127.0.0.1:2080", changeOrigin: true } },
  },
});
