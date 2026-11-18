/* SatsGuard E2E smoke test (headless browser on the BUILT single-file PWA) */
"use strict";
const { chromium } = require("/home/z/.npm-global/lib/node_modules/playwright");
(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 430, height: 900 } });
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.goto("file:///home/z/my-project/agentpay/app/dist/index.html");
  await page.waitForTimeout(600);

  const t = (name, ok) => console.log(ok ? "  ✓ " + name : "  ✗ FAIL: " + name);
  t("home renders balance", (await page.textContent("#balance")).includes("523,750"));
  t("gauge shows 0%", (await page.textContent("#pct")).trim() === "0%");

  await page.click("[data-go='s-create']");
  t("create screen shows budget", (await page.textContent("#capBig")) === "1,000,000");
  await page.click("#signBtn"); // signs mandate (real schnorr) + auto-runs demo
  await page.waitForTimeout(6800); // 4 staged payments

  const chips = await page.locator("#timeline .chip").allTextContents();
  t("3 PAID + 1 REJECTED — LIMIT", chips.filter((c) => c === "PAID").length === 3 && chips.some((c) => c === "REJECTED — LIMIT"));
  t("gauge updated (75%)", (await page.textContent("#pct")).trim() === "75%");
  t("warning card visible", await page.locator("#warnLimit").isVisible());
  const txs = await page.locator("#timeline .tx span").allTextContents();
  t("tx hashes rendered", txs.length >= 8);

  await page.click("[data-go='s-security']");
  await page.click("#revokeBtn");
  await page.waitForTimeout(800);
  const sys = await page.textContent("#sysTxt");
  t("revoked — agent has zero rights", sys.includes("revoked"));

  // every path blocked after revocation
  await page.click("nav a[data-go='s-settings']");
  await page.click("#runDemo");
  await page.waitForTimeout(6500);
  const chips2 = await page.locator("#timeline .chip").allTextContents();
  t("post-revocation spends all REJECTED — REVOKED", chips2.slice(0, 4).every((c) => c.startsWith("REJECTED")));

  await page.click("#verifyBtn");
  const v = await page.textContent("#verifyLine");
  t("hash chain intact after 8 ops", v.includes("hash chain intact"));

  // reload → persistence via localStorage
  await page.reload(); await page.waitForTimeout(700);
  t("state persists across reload", (await page.textContent("#pct")).trim() !== "0%");

  console.log(errors.length ? "PAGE ERRORS:\n" + errors.join("\n") : "no page errors");
  await browser.close();
})().catch((e) => { console.error("E2E FAIL:", e.message); process.exit(1); });
