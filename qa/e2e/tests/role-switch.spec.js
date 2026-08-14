const { test, expect } = require("@playwright/test");

test.describe("Role selector on the login screen", () => {
  test("defaults to Admin and switches to Auditor / Auditee", async ({ page }) => {
    await page.goto("/");

    await expect(page.locator("#role-admin-btn")).toHaveClass(/active/);

    await page.click("#role-auditor-btn");
    await expect(page.locator("#role-auditor-btn")).toHaveClass(/active/);
    await expect(page.locator("#role-admin-btn")).not.toHaveClass(/active/);

    await page.click("#role-auditee-btn");
    await expect(page.locator("#role-auditee-btn")).toHaveClass(/active/);
    await expect(page.locator("#role-auditor-btn")).not.toHaveClass(/active/);
  });

  test("role description text updates per role", async ({ page }) => {
    await page.goto("/");
    const before = await page.locator("#role-desc").textContent();

    await page.click("#role-auditor-btn");
    const after = await page.locator("#role-desc").textContent();

    expect(after).not.toEqual(before);
  });
});
