const { defineConfig } = require('@playwright/test');

module.exports = defineConfig({
  testDir: '.',
  testMatch: '*.spec.cjs',
  fullyParallel: true,
  workers: 2,
  reporter: 'list',
  use: {
    browserName: 'chromium',
    reducedMotion: 'reduce',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
});
