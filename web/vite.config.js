import { defineConfig } from 'vite';

// `npm run dev` proxies the API to a local `asname --rest`, so the UI talks
// to it same-origin just as it does when asname serves the built files.
const target = process.env.ASNAME_API || 'http://127.0.0.1:8086';

export default defineConfig({
  base: './',
  server: {
    proxy: {
      '/v1': { target, changeOrigin: false },
      '/health': { target, changeOrigin: false },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 2048,
  },
});
