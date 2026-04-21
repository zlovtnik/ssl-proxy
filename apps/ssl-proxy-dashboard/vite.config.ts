import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  resolve: {
    conditions: ['browser']
  },
  server: {
    port: 5173,
    proxy: {
      '/hosts': {
        target: 'http://127.0.0.1:3002',
        changeOrigin: true,
        headers: { 'x-api-key': 'test' }
      },
      '/stats': {
        target: 'http://127.0.0.1:3002',
        changeOrigin: true,
        headers: { 'x-api-key': 'test' }
      },
      '/devices': {
        target: 'http://127.0.0.1:3002',
        changeOrigin: true,
        headers: { 'x-api-key': 'test' }
      },
      '/health': { target: 'http://127.0.0.1:3002', changeOrigin: true },
      '/ready': { target: 'http://127.0.0.1:3002', changeOrigin: true }
    }
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./vitest.setup.ts']
  }
});
