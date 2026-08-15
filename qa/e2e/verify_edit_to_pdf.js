const { chromium } = require("playwright");
const { TOTP, Secret } = require("otpauth");
const path = require("path");

const BASE = "http://localhost:8001";
const USERNAME = "e2e-verify-report@test.local";
const PASSWORD = "E2eReport#2026!";
const TOTP_SECRET = "LI2TZ2LKLKWTLM4SIZ3QQXI5URV4ZZPC";
const SESSION_ID = "editreporttest-001";
const SESSION_TITLE = "Edit-to-Report Verification Session";
const MARKER = "MARKER_" + Date.now() + "_AUDITOR_EDITED_THIS_FINDING";
const DL_DIR = "C:\\Users\\HP\\AppData\\Local\\Temp\\claude\\c--Users-HP-Desktop-audit-test-box\\02cf81eb-ef23-4252-8502-b8b1a1f89d81\\scratchpad";
const SHOT_DIR = DL_DIR + "\\screenshots";

function currentOtp() {
  const totp = new TOTP({ secret: Secret.fromBase32(TOTP_SECRET), digits: 6, period: 30 });
  return totp.generate();
}

(async () => {
  const fs = require("fs");
  fs.mkdirSync(SHOT_DIR, { recursive: true });

  const browser = await chromium.launch({ args: ["--no-sandbox"] });
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, acceptDownloads: true });
  const results = { marker: MARKER };

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

    // Select our seeded session (equivalent to clicking it in the sidebar) and
    // switch to the Audit Records tab, exactly like switchRecentSession() +
    // switchTab() do when a user clicks through the real UI.
    await page.evaluate(({ sid, title }) => {
      switchRecentSession(sid, title);
      switchTab("tab-audit-records");
    }, { sid: SESSION_ID, title: SESSION_TITLE });

    await page.waitForSelector("#findings-container", { state: "visible", timeout: 10000 });
    await page.waitForFunction(() => {
      const c = document.getElementById("findings-container");
      return c && c.innerText && c.innerText.includes("5.1");
    }, { timeout: 15000 });

    await page.screenshot({ path: `${SHOT_DIR}/6_findings_before_edit.png` });

    // Click the real "Modify" button for our finding.
    await page.click('button:has-text("Modify")');
    await page.waitForSelector("#edit-finding-modal.active", { timeout: 10000 });

    // Edit via the real form fields, exactly what a human would type.
    await page.fill("#edit-finding-reasoning", MARKER);
    await page.fill("#edit-finding-recommendation", "Auditor-added remediation: " + MARKER);
    await page.screenshot({ path: `${SHOT_DIR}/7_edit_modal_filled.png` });

    // Submit via the real form submit handler.
    await page.click('#edit-finding-modal button[type="submit"]');
    await page.waitForSelector("#edit-finding-modal", { state: "hidden", timeout: 10000 });
    results.editSubmitted = true;
    results.descriptionAfterEdit = await page.locator("#findings-container").innerText();

    // Switch to Audit Report tab and click the real PDF export button.
    await page.evaluate(() => switchTab("tab-audit-report"));
    await page.waitForSelector("#btn-export-pdf", { state: "visible", timeout: 10000 });

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 30000 }),
      page.click("#btn-export-pdf"),
    ]);
    const pdfPath = path.join(DL_DIR, "verify_report.pdf");
    await download.saveAs(pdfPath);
    results.pdfSavedTo = pdfPath;
    results.pdfSuggestedFilename = download.suggestedFilename();

    console.log("RESULTS_JSON_START");
    console.log(JSON.stringify(results, null, 2));
    console.log("RESULTS_JSON_END");
  } catch (err) {
    await page.screenshot({ path: `${SHOT_DIR}/ERROR_edit_to_pdf.png` }).catch(() => {});
    results.error = String(err);
    console.log("RESULTS_JSON_START");
    console.log(JSON.stringify(results, null, 2));
    console.log("RESULTS_JSON_END");
  } finally {
    await browser.close();
  }
})();
