const { chromium } = require("playwright");
const { TOTP, Secret } = require("otpauth");

const BASE = "http://localhost:8001";
const USERNAME = "e2e-scanfail@test.local";
const PASSWORD = "E2eScan#2026!";
const TOTP_SECRET = "3NUALNONSRRIWMHB732OQ7A5F5RUBE3D";
const SHOT_DIR = "C:\\Users\\HP\\AppData\\Local\\Temp\\claude\\c--Users-HP-Desktop-audit-test-box\\02cf81eb-ef23-4252-8502-b8b1a1f89d81\\scratchpad\\screenshots";

function currentOtp() {
  const totp = new TOTP({ secret: Secret.fromBase32(TOTP_SECRET), digits: 6, period: 30 });
  return totp.generate();
}

(async () => {
  const fs = require("fs");
  fs.mkdirSync(SHOT_DIR, { recursive: true });

  const browser = await chromium.launch({ args: ["--no-sandbox"] });
  const page = await browser.newPage({ viewport: { width: 1400, height: 1000 } });

  const failedRequests = [];
  const responses = [];
  page.on("requestfailed", (req) => {
    failedRequests.push({ url: req.url(), method: req.method(), failure: req.failure()?.errorText });
  });
  page.on("response", (res) => {
    if (res.url().includes("/audit/start")) {
      responses.push({ url: res.url(), status: res.status(), ok: res.ok() });
    }
  });
  page.on("console", (msg) => { if (msg.type() === "error") console.log("[BROWSER CONSOLE ERROR]", msg.text()); });
  page.on("pageerror", (err) => console.log("[BROWSER PAGE ERROR]", err.message));
  page.on("dialog", async (dialog) => {
    console.log("[DIALOG]", dialog.message());
    await dialog.accept();
  });

  const results = {};
  try {
    await page.goto(BASE, { waitUntil: "domcontentloaded" });
    await page.click("#role-auditor-btn");
    await page.fill("#username-input", USERNAME);
    await page.fill("#password-input", PASSWORD);
    await page.click("#auth-submit-btn");
    await page.waitForSelector("#otp-form", { state: "visible", timeout: 15000 });
    await page.fill("#otp-input", currentOtp());
    await page.click('#otp-form button[type="submit"]');
    await page.waitForSelector("#app-shell", { state: "visible", timeout: 15000 });
    results.loggedIn = true;

    // Create a real audit session first (client generates activeSessionId, matching
    // what a real user does via "+ New Audit Session" before this screen is usable).
    await page.evaluate(() => startNewAuditSession(true, "VAPT E2E Test Session"));
    await page.waitForTimeout(500);
    results.activeSessionId = await page.evaluate(() => typeof activeSessionId !== "undefined" ? activeSessionId : null);

    // Select VAPT framework, matching the user's screenshot
    await page.selectOption("#framework-select", "VAPT");
    await page.waitForTimeout(1000);

    // Ensure at least one control is checked (AI Auto-Scoping is default-active already)
    const checkedCount = await page.evaluate(() => {
      const boxes = document.querySelectorAll("#controls-checkbox-container input[type='checkbox']");
      let checked = Array.from(boxes).filter(cb => cb.checked).length;
      if (checked === 0 && boxes.length > 0) {
        boxes.forEach(cb => cb.checked = true);
        checked = boxes.length;
      }
      return checked;
    });
    results.checkedControlsCount = checkedCount;

    await page.screenshot({ path: `${SHOT_DIR}/8_before_start_scan.png` });

    // Click the real "RUN AUDIT SCAN" button
    await page.click("#run-analysis-btn");
    await page.waitForTimeout(4000);

    await page.screenshot({ path: `${SHOT_DIR}/9_after_start_scan.png` });

    results.failedRequests = failedRequests;
    results.startResponses = responses;

    console.log("RESULTS_JSON_START");
    console.log(JSON.stringify(results, null, 2));
    console.log("RESULTS_JSON_END");
  } catch (err) {
    await page.screenshot({ path: `${SHOT_DIR}/ERROR_start_scan.png` }).catch(() => {});
    results.error = String(err);
    results.failedRequests = failedRequests;
    results.startResponses = responses;
    console.log("RESULTS_JSON_START");
    console.log(JSON.stringify(results, null, 2));
    console.log("RESULTS_JSON_END");
  } finally {
    await browser.close();
  }
})();
