/**
 * dsh-browser-validate — confirm client-side execution in a real browser.
 *
 * WHY THIS EXISTS
 * Half the web bug classes cannot be confirmed from an HTTP response:
 *   - XSS: the payload is only a bug if the browser EXECUTES it. A reflected string is not
 *     an XSS. XBOW's stated validator for exactly this is "a headless browser visits the
 *     target site to verify that the JavaScript payload was truly executed".
 *   - DOM XSS: no server involvement at all, invisible to any HTTP diff.
 *   - Client-side authz: the guard lives in JavaScript.
 * The pipeline previously had no browser validator, and Playwright was declared in
 * package.json but never installed, so recon-11 silently degraded. This plugin fails
 * LOUDLY when the browser is missing instead of returning a quiet false negative.
 *
 * HOW CONFIRMATION WORKS
 * Execution is detected by observation, never by assumption:
 *   1. a dialog handler (alert/confirm/prompt) firing, and/or
 *   2. a marker the payload is expected to set (default `window.__bh_xss`), and/or
 *   3. a console message / page error matching a supplied pattern.
 * If none fire, the result is `executed: false` — not confirmed, do not report.
 */

export const name = "browser-validate";
export const inject = ["tools"];

let chromium = null;
let importError = null;
try {
  ({ chromium } = await import("playwright"));
} catch (e) {
  importError = e.message;
}

/** Structured, loud failure instead of a silent false negative. */
function unavailable(reason) {
  return JSON.stringify({
    executed: false,
    available: false,
    error: reason,
    note:
      "Browser validation is UNAVAILABLE, so no conclusion can be drawn about client-side " +
      "execution. Install with: npm install && npx playwright install chromium",
  });
}

export function apply(ctx, config = {}) {
  const cfg = { timeoutMs: 20000, settleMs: 1200, ...config };

  async function withBrowser(fn) {
    if (!chromium) {
      return unavailable(importError ? `playwright not importable: ${importError}` : "playwright not installed");
    }
    let browser;
    try {
      browser = await chromium.launch({ headless: true });
    } catch (e) {
      return unavailable(`chromium failed to launch (browsers not installed?): ${e.message}`);
    }
    try {
      return await fn(browser);
    } finally {
      await browser.close().catch(() => {});
    }
  }

  ctx.tools.register({
    name: "validate_xss_browser",
    description:
      "Load a URL in headless Chromium and confirm the payload ACTUALLY EXECUTED (dialog fired, marker set, or console pattern matched). Without this, a reflected payload is not an XSS finding. Returns executed=true/false plus the raw observations.",
    parameters: {
      type: "object",
      properties: {
        url: { type: "string", description: "Full URL including the injected payload." },
        marker: {
          type: "string",
          description: "JS expression evaluated after load; default checks window.__bh_xss. Set to 'null' to rely on dialogs/console only.",
        },
        consolePattern: { type: "string", description: "Regex; a matching console message or page error counts as execution." },
        settleMs: { type: "number", description: "Wait after load for async payloads (default 1200)." },
        cookie: { type: "string", description: "Optional Cookie header value to send with the navigation." },
      },
      required: ["url"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const settleMs = Number.isFinite(args.settleMs) ? args.settleMs : cfg.settleMs;
      const markerExpr = args.marker === null || args.marker === "null" ? null : args.marker || "window.__bh_xss";
      const consoleRe = args.consolePattern ? new RegExp(args.consolePattern, "i") : null;

      return withBrowser(async (browser) => {
        const context = await browser.newContext({
          ignoreHTTPSErrors: true,
          userAgent: "Mozilla/5.0 (bugbounty-validation; authorized testing)",
        });
        if (args.cookie) {
          // Accept a single "name=value" pair and scope it to the target host.
          const raw = String(args.cookie);
          const eq = raw.indexOf("=");
          if (eq > 0) {
            try {
              const u = new URL(args.url);
              await context.addCookies([
                { name: raw.slice(0, eq), value: raw.slice(eq + 1), domain: u.hostname, path: "/" },
              ]);
            } catch {
              /* malformed URL: navigate unauthenticated rather than failing the whole check */
            }
          }
        }
        const page = await context.newPage();
        const dialogs = [];
        const consoleHits = [];
        page.on("dialog", async (d) => {
          dialogs.push({ type: d.type(), message: d.message() });
          await d.dismiss().catch(() => {});
        });
        page.on("console", (msg) => {
          const t = msg.text();
          if (consoleRe && consoleRe.test(t)) consoleHits.push(t);
        });
        page.on("pageerror", (err) => {
          const t = String(err && err.message ? err.message : err);
          if (consoleRe && consoleRe.test(t)) consoleHits.push(t);
        });

        let navError = null;
        try {
          await page.goto(args.url, { waitUntil: "load", timeout: cfg.timeoutMs });
        } catch (e) {
          navError = e.message;
        }
        await page.waitForTimeout(settleMs);

        let markerValue = null;
        let markerError = null;
        if (markerExpr) {
          try {
            markerValue = await page.evaluate(markerExpr);
          } catch (e) {
            markerError = e.message;
          }
        }

        const executed = dialogs.length > 0 || consoleHits.length > 0 || Boolean(markerValue);
        const evidence = {
          dialogs,
          console_hits: consoleHits,
          marker: markerExpr,
          marker_value: markerValue === undefined ? null : markerValue,
          marker_error: markerError,
          navigation_error: navError,
        };

        return JSON.stringify({
          available: true,
          executed,
          confidence: executed ? (dialogs.length || markerValue ? "high" : "medium") : "none",
          url: args.url,
          evidence,
          note: executed
            ? "Payload executed in the browser — this is a real client-side execution, not just a reflection."
            : navError
              ? `Page did not load cleanly (${navError}); no conclusion.`
              : "No dialog, marker or console match. Payload did NOT execute — not an XSS. Do not report.",
        });
      });
    },
  });

  ctx.tools.register({
    name: "browser_snapshot",
    description:
      "Load a page in headless Chromium and return observable facts: final URL (post-JS redirects), title, forms, links, scripts and whether the page threw. Useful for client-side redirect chains and SPAs the HTTP crawler cannot see.",
    parameters: {
      type: "object",
      properties: {
        url: { type: "string" },
        settleMs: { type: "number" },
      },
      required: ["url"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const settleMs = Number.isFinite(args.settleMs) ? args.settleMs : cfg.settleMs;
      return withBrowser(async (browser) => {
        const page = await browser.newPage({ ignoreHTTPSErrors: true });
        const errors = [];
        page.on("pageerror", (e) => errors.push(String(e.message || e)));
        let navError = null;
        try {
          await page.goto(args.url, { waitUntil: "load", timeout: cfg.timeoutMs });
        } catch (e) {
          navError = e.message;
        }
        await page.waitForTimeout(settleMs);
        const snap = await page.evaluate(() => ({
          title: document.title,
          url: location.href,
          forms: [...document.querySelectorAll("form")].map((f) => ({
            action: f.getAttribute("action") || "",
            method: (f.getAttribute("method") || "get").toLowerCase(),
            inputs: [...f.querySelectorAll("input,select,textarea")].map((i) => i.getAttribute("name")).filter(Boolean),
          })),
          links: [...new Set([...document.querySelectorAll("a[href]")].map((a) => a.href))].slice(0, 200),
          scripts: [...new Set([...document.querySelectorAll("script[src]")].map((s) => s.src))].slice(0, 100),
        }));
        return JSON.stringify({
          available: true,
          request_url: args.url,
          final_url: snap.url,
          client_side_redirect: snap.url !== args.url,
          title: snap.title,
          forms: snap.forms,
          link_count: snap.links.length,
          links: snap.links.slice(0, 50),
          scripts: snap.scripts.slice(0, 30),
          page_errors: errors.slice(0, 10),
          navigation_error: navError,
        });
      });
    },
  });

  /**
   * Perceptual image hash, computed by the browser's own image decoder.
   *
   * Gap this closes: asset dedup had no visual half, and the honest reason was that a
   * perceptual hash needs an image decoder. The browser already IS one -- so we decode via
   * canvas instead of adding an image library or (worse) faking it with a byte hash that
   * would differ for visually identical screenshots.
   *
   * Returns dHash and aHash as 64-bit hex strings.
   */
  async function hashDataUrl(page, dataUrl, size = 16) {
    return page.evaluate(
      async ({ dataUrl: src, size: s }) => {
        const img = new Image();
        img.src = src;
        await img.decode();
        const c = document.createElement("canvas");
        c.width = s + 1;
        c.height = s;
        const ctx = c.getContext("2d");
        ctx.drawImage(img, 0, 0, s + 1, s);
        const d = ctx.getImageData(0, 0, s + 1, s).data;
        const gray = [];
        for (let i = 0; i < d.length; i += 4) gray.push(0.299 * d[i] + 0.587 * d[i + 1] + 0.114 * d[i + 2]);
        const toHex = (bits) => {
          let hex = "";
          for (let i = 0; i < bits.length; i += 4) hex += parseInt(bits.slice(i, i + 4).padEnd(4, "0"), 2).toString(16);
          return hex;
        };
        let dbits = "";
        let abits = "";
        const avg = gray.reduce((a, b) => a + b, 0) / gray.length;
        for (let y = 0; y < s; y += 1) {
          for (let x = 0; x < s; x += 1) {
            const px = gray[y * (s + 1) + x];
            dbits += px < gray[y * (s + 1) + x + 1] ? "1" : "0";
            abits += px < avg ? "1" : "0";
          }
        }
        return { dhash: toHex(dbits), ahash: toHex(abits) };
      },
      { dataUrl, size }
    );
  }

  ctx.tools.register({
    name: "screenshot_hash",
    description:
      "Load a URL, screenshot it, and return a perceptual (dHash/aHash) fingerprint of the rendering. Visually identical pages on different hostnames produce near-identical hashes, which is how cloned/staging assets get collapsed. Uses the browser's image decoder, so no image library is needed.",
    parameters: {
      type: "object",
      properties: {
        url: { type: "string" },
        settleMs: { type: "number" },
      },
      required: ["url"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const settleMs = Number.isFinite(args.settleMs) ? args.settleMs : cfg.settleMs;
      return withBrowser(async (browser) => {
        const page = await browser.newPage({ ignoreHTTPSErrors: true });
        try {
          await page.goto(args.url, { waitUntil: "load", timeout: cfg.timeoutMs });
        } catch (e) {
          return JSON.stringify({ available: true, url: args.url, error: `navigation failed: ${e.message}` });
        }
        await page.waitForTimeout(settleMs);
        const shot = await page.screenshot({ type: "png", fullPage: true });
        const hash = await hashDataUrl(page, `data:image/png;base64,${shot.toString("base64")}`);
        return JSON.stringify({
          available: true,
          url: args.url,
          final_url: page.url(),
          title: await page.title(),
          ...hash,
        });
      });
    },
  });

  ctx.tools.register({
    name: "hash_images",
    description:
      "Perceptual-hash local image files (or a directory of them) using the browser's decoder. Feed the resulting hashes to dedup_assets to group visually identical assets.",
    parameters: {
      type: "object",
      properties: {
        paths: { type: "string", description: "Image files or directories, one per line." },
      },
      required: ["paths"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const { readFile, readdir, stat } = await import("node:fs/promises");
      const { join, extname } = await import("node:path");
      const MIME = { ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp", ".gif": "image/gif" };
      const targets = String(args.paths || "").split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
      const files = [];
      const walk = async (p) => {
        let st;
        try {
          st = await stat(p);
        } catch {
          return;
        }
        if (st.isDirectory()) {
          for (const e of await readdir(p, { withFileTypes: true })) await walk(join(p, e.name));
        } else if (MIME[extname(p).toLowerCase()]) {
          files.push(p);
        }
      };
      for (const t of targets) await walk(t);
      if (!files.length) return JSON.stringify({ available: true, hashed: 0, images: [], note: "no image files found" });

      return withBrowser(async (browser) => {
        const page = await browser.newPage();
        await page.goto("about:blank");
        const images = [];
        for (const f of files.slice(0, 200)) {
          try {
            const buf = await readFile(f);
            const mime = MIME[extname(f).toLowerCase()];
            const h = await hashDataUrl(page, `data:${mime};base64,${buf.toString("base64")}`);
            images.push({ id: f, ...h });
          } catch (e) {
            images.push({ id: f, error: e.message });
          }
        }
        return JSON.stringify({ available: true, hashed: images.filter((i) => i.dhash).length, images });
      });
    },
  });

  ctx.tools.register({
    name: "hash_screenshots",
    description:
      "Screenshot many URLs in ONE browser and perceptual-hash each. Batch variant of screenshot_hash: launching a browser per host is far too slow for a real scope. Feed the output straight to dedup_by_hash.",
    parameters: {
      type: "object",
      properties: {
        urls: { type: "string", description: "URLs, one per line." },
        limit: { type: "number", description: "Max URLs to shoot (default 30)." },
        settleMs: { type: "number" },
      },
      required: ["urls"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const urls = String(args.urls || "").split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
      const limit = Number.isFinite(args.limit) ? args.limit : 30;
      const settleMs = Number.isFinite(args.settleMs) ? args.settleMs : 600;
      if (!urls.length) return JSON.stringify({ available: true, hashed: 0, images: [] });

      return withBrowser(async (browser) => {
        const context = await browser.newContext({ ignoreHTTPSErrors: true });
        const page = await context.newPage();
        const images = [];
        for (const u of urls.slice(0, limit)) {
          try {
            await page.goto(u, { waitUntil: "load", timeout: cfg.timeoutMs });
            await page.waitForTimeout(settleMs);
            const shot = await page.screenshot({ type: "png", fullPage: true });
            const h = await hashDataUrl(page, `data:image/png;base64,${shot.toString("base64")}`);
            images.push({ id: u, ...h });
          } catch (e) {
            images.push({ id: u, error: String(e.message || e) });
          }
        }
        return JSON.stringify({
          available: true,
          hashed: images.filter((i) => i.dhash).length,
          failed: images.filter((i) => i.error).length,
          images,
        });
      });
    },
  });

  console.log(
    "[browser-validate] registered:",
    chromium
      ? "validate_xss_browser, browser_snapshot, screenshot_hash, hash_images (chromium available)"
      : "UNAVAILABLE — run npx playwright install chromium"
  );
}
