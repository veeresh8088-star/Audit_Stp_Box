// @ts-check
const { defineConfig, devices } = require("@playwright/test");

// App must already be running (e.g. via run_all.bat) before these tests execute.
// Self-signed cert.pem/key.pem per CLAUDE.md, so HTTPS errors are ignored here.
module.exports = defineConfig({
  testDir: "./tests",
  fullyParallel: false, // audit sessions/uploads are stateful; run serially to avoid cross-test interference
  retries: process.env.CI ? 1 : 0,
  reporter: [["html", { open: "never" }], ["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL || "https://localhost:8000",
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});
