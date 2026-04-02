import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { nodePolyfills } from 'vite-plugin-node-polyfills'

export default defineConfig({
  plugins: [
    react(),
    nodePolyfills({
      include: ['buffer', 'process'],
      // Disable global injection - we'll handle it via define
      globals: {
        Buffer: true,
        global: false,  // Disable - handled via define
        process: true,
      },
      // Use protocolImports: false to avoid resolution issues with WASM
      protocolImports: false,
    }),
  ],
  // Define global as globalThis for browser compatibility
  define: {
    global: 'globalThis',
  },
  base: '/',
  build: {
    outDir: '../static',
    emptyOutDir: true,
    // Increase chunk size warning limit for large ZK proving keys
    chunkSizeWarningLimit: 5000,
    rollupOptions: {
      // Handle the WASM module's global reference
      onwarn(warning, warn) {
        // Ignore warnings about module externalization
        if (warning.code === 'MODULE_LEVEL_DIRECTIVE' ||
            (warning.message && warning.message.includes('externalized'))) {
          return;
        }
        warn(warning);
      },
    },
  },
  server: {
    proxy: {
      '/account': 'http://localhost:8333',
      '/accounts': 'http://localhost:8333',
      '/transactions': 'http://localhost:8333',
      '/tx': 'http://localhost:8333',
      '/chain': 'http://localhost:8333',
      '/block': 'http://localhost:8333',
      '/mempool': 'http://localhost:8333',
      '/miner': 'http://localhost:8333',
      '/blocks': 'http://localhost:8333',
      '/peers': 'http://localhost:8333',
      '/debug': 'http://localhost:8333',
      // Shielded wallet API endpoints
      '/outputs': 'http://localhost:8333',
      '/witness': 'http://localhost:8333',
      '/nullifiers': 'http://localhost:8333',
      // Faucet API
      '/faucet': 'http://localhost:8333',
    },
    // Allow serving circuit files from public directory
    fs: {
      allow: ['..'],
    },
  },
  // Configure WASM handling
  assetsInclude: ['**/*.wasm', '**/*.zkey'],
  optimizeDeps: {
    exclude: ['tsn-plonky2-wasm'],
  },
})
