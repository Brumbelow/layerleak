const assert = require("node:assert/strict");
const { readFile } = require("node:fs/promises");
const path = require("node:path");
const { test } = require("node:test");
const { chromium } = require("playwright");

const root = path.resolve(__dirname, "../..");
const origin = "https://demo.test";

async function openDemo(t, fixture, failed = false) {
  const browser = await chromium.launch({
    executablePath: process.env.DEMO_BROWSER_PATH || undefined,
  });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const assets = new Map([
    ["/docs/demo/", [await readFile(path.join(root, "web/docs/demo/index.html")), "text/html"]],
    ["/assets/demo.js", [await readFile(path.join(root, "web/assets/demo.js")), "text/javascript"]],
  ]);
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== origin) return route.abort();
    if (url.pathname === "/assets/demo-data.json") {
      return route.fulfill({ status: failed ? 503 : 200, json: fixture });
    }
    const asset = assets.get(url.pathname);
    if (!asset) return route.fulfill({ status: 200, body: "" });
    const [body, contentType] = asset;
    return route.fulfill({ contentType, body });
  });
  await page.clock.install();
  await page.goto(`${origin}/docs/demo/`);
  await page.waitForFunction(() =>
    document.getElementById("demo-command").textContent !== "loading demo fixture..."
  );
  return page;
}

function fixture() {
  return {
    command: "example replay",
    frames: [
      { terminal: "first transcript", status: "first status", delay_ms: 100 },
      { terminal: "last transcript", status: "last status", delay_ms: 200 },
    ],
    stats: [{ label: "Status", value: "completed" }],
    table_order: ["sample", "other"],
    tables: {
      sample: {
        description: "Sample rows",
        columns: ["empty", "absent", "blank", "enabled", "count", "details", "text"],
        // eslint-disable-next-line xss/no-mixed-html -- Harmless fixture markup must be displayed as literal cell text.
        rows: [{ empty: null, blank: "", enabled: false, count: 0, details: { ok: true }, text: "<em>plain table text</em>" }],
      },
      other: { description: "Other rows", columns: ["name"], rows: [{ name: "second" }, { name: "third" }] },
    },
  };
}

async function completeReplay(page) {
  await page.locator("#demo-start").click();
  await page.clock.runFor(300);
}

test("status fixture text stays literal while its label remains strong", async (t) => {
  const data = fixture();
  // eslint-disable-next-line xss/no-mixed-html -- This controlled input checks that status text is never parsed as markup.
  data.frames[0].status = "<em>plain status text</em> & done";
  const page = await openDemo(t, data);
  await page.locator("#demo-start").click();
  // eslint-disable-next-line xss/no-mixed-html -- The assertion compares literal text, not rendered HTML.
  assert.equal(await page.locator("#demo-status").textContent(), "Status: <em>plain status text</em> & done");
  assert.equal(await page.locator("#demo-status strong").textContent(), "Status:");
  assert.equal(await page.locator("#demo-status em").count(), 0);
});

test("replay advances frames, gates tabs, formats cells and resets on replay", async (t) => {
  const page = await openDemo(t, fixture());
  assert.equal(await page.locator("#demo-replay").isDisabled(), true);
  assert.equal(await page.locator("#demo-tabs button").first().isDisabled(), true);
  await page.locator("#demo-start").click();
  assert.equal(await page.locator("#demo-terminal").textContent(), "first transcript");
  assert.equal(await page.locator("#demo-start").isDisabled(), true);
  await page.clock.runFor(100);
  assert.equal(await page.locator("#demo-terminal").textContent(), "last transcript");
  assert.equal(await page.locator("#demo-replay").isDisabled(), true);
  await page.clock.runFor(200);
  assert.equal(await page.locator("#demo-replay").isDisabled(), false);
  assert.equal(await page.locator("#demo-stats p").textContent(), "completed");
  // eslint-disable-next-line xss/no-mixed-html -- Cell text must retain the fixture's literal markup characters.
  assert.deepEqual(await page.locator("tbody td").allTextContents(), ["—", "—", "—", "false", "0", '{"ok":true}', "<em>plain table text</em>"]);
  assert.equal(await page.locator("tbody em").count(), 0);
  await page.getByRole("button", { name: "other", exact: true }).click();
  assert.deepEqual(await page.locator("tbody td").allTextContents(), ["second", "third"]);
  assert.equal(await page.locator("#table-meta").textContent(), "Other rows · 2 rows");
  assert.equal(await page.getByRole("button", { name: "other", exact: true }).getAttribute("aria-selected"), "true");
  await page.locator("#demo-replay").click();
  assert.equal(await page.locator("#demo-terminal").textContent(), "first transcript");
  assert.equal(await page.locator("#demo-tabs button").first().isDisabled(), true);
  assert.equal(await page.locator("tbody").count(), 0);
  await page.clock.runFor(300);
  assert.equal(await page.getByRole("button", { name: "sample", exact: true }).getAttribute("aria-selected"), "true");
});

test("missing table and row fields do not resolve inherited object properties", async (t) => {
  const data = fixture();
  data.tables.sample.columns = ["constructor", "toString", "missing"];
  data.tables.sample.rows = [{ constructor: "own fixture field" }];
  data.table_order.push("constructor");
  const page = await openDemo(t, data);
  await completeReplay(page);
  assert.deepEqual(await page.locator("tbody td").allTextContents(), ["own fixture field", "—", "—"]);
  await page.getByRole("button", { name: "constructor", exact: true }).click();
  assert.equal(await page.locator("#table-meta").textContent(), "Missing table fixture");
  assert.equal(await page.locator("#demo-table-wrap").textContent(), "Unknown table.");
});

test("fixture load failure leaves a readable status and disables starting", async (t) => {
  const page = await openDemo(t, {}, true);
  assert.equal(await page.locator("#demo-start").isDisabled(), true);
  assert.equal(await page.locator("#demo-status strong").textContent(), "Status:");
  assert.match(await page.locator("#demo-status").textContent(), /failed to load/);
  assert.match(await page.locator("#demo-table-wrap").textContent(), /could not be loaded/);
});

test("the checked-in fixture completes and renders its initial table", async (t) => {
  const data = JSON.parse(await readFile(path.join(root, "web/assets/demo-data.json"), "utf8"));
  const page = await openDemo(t, data);
  await page.locator("#demo-start").click();
  await page.clock.runFor(8000);
  assert.equal(await page.locator("#demo-replay").isDisabled(), false);
  assert.equal(await page.locator("#demo-status").textContent(), "Status: showing final summary");
  assert.equal(await page.getByRole("button", { name: "repositories", exact: true }).getAttribute("aria-selected"), "true");
  assert.equal(await page.locator("tbody tr").count(), 1);
  assert.equal(await page.locator("#demo-tabs button:disabled").count(), 0);
});
