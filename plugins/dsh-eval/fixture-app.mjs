#!/usr/bin/env node
/**
 * Intentionally vulnerable fixture for evaluating bughive itself.
 *
 * A LOCAL BENCHMARK TARGET in the spirit of OWASP Juice Shop / DVWA. It exists so the tool
 * can be measured (true positives, false positives, false negatives per class) instead of
 * being changed on vibes. Published leaders all attribute their progress to benchmarking.
 *
 * SAFETY
 *   - Binds 127.0.0.1 ONLY. Never exposes a public interface.
 *   - SSRF (`/fetch`) refuses any non-loopback target, so the fixture cannot be used as a
 *     request forwarder.
 *   - XXE entity reads are confined to ./fixture-data/ inside the plugin directory, so
 *     entity expansion is genuinely demonstrable without giving up the filesystem.
 *   - Every vulnerability is deliberate, annotated, and listed in ground-truth.json.
 *
 * Difficulty tiers (see ground-truth.json): L1 obvious, L2 needs a second request or a
 * second identity, L3 needs chaining or state awareness.
 *
 * Usage: node fixture-app.mjs [--port 8099]
 */

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, normalize, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(HERE, "fixture-data");

const args = process.argv.slice(2);
const portArg = args.indexOf("--port");
const PORT = portArg !== -1 ? Number(args[portArg + 1]) : 8099;
const BIND = "127.0.0.1";

const USERS = [
  { id: 1, name: "alice", email: "alice@example.test", role: "user", apiKey: "AKIAIOSFODNN7EXAMPLE", balance: 100 },
  { id: 2, name: "bob", email: "bob@example.test", role: "user", apiKey: "AKIAI44QH8DHBEXAMPLE", balance: 100 },
  { id: 3, name: "root", email: "root@example.test", role: "admin", apiKey: "AKIAJWEXAMPLEKEY1234", balance: 100 },
];
const ITEMS = [
  { id: 1, owner: "alice", title: "alice-private-note", secret: "FLAG{alice_private}" },
  { id: 2, owner: "bob", title: "bob-private-note", secret: "FLAG{bob_private}" },
];
const COUPONS = { SAVE10: { discount: 10, remaining: 1 } };

const j = (res, code, obj, extra = {}) => {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body), ...extra });
  res.end(body);
};
const html = (res, code, body) => {
  res.writeHead(code, { "Content-Type": "text/html; charset=utf-8" });
  res.end(body);
};
const readBody = (req) =>
  new Promise((resolve) => {
    const c = [];
    req.on("data", (d) => c.push(d));
    req.on("end", () => resolve(Buffer.concat(c).toString("utf8")));
  });

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${BIND}:${PORT}`);
  const p = url.pathname;
  const m = req.method;

  // ============================================================== L1: obvious

  // BUG F1 - IDOR (read): no authorization check on a numeric object id.
  let mt = p.match(/^\/api\/users\/(\d+)$/);
  if (mt && m === "GET") {
    const u = USERS.find((x) => x.id === Number(mt[1]));
    return u ? j(res, 200, u) : j(res, 404, { error: "not found" });
  }

  // BUG F2 - missing authentication on an admin surface.
  if (p === "/admin/users") return j(res, 200, { users: USERS });

  // BUG F3 - reflected XSS: interpolated with no escaping.
  if (p === "/search") {
    const q = url.searchParams.get("q") || "";
    return html(res, 200, `<!doctype html><html><body><h1>Results</h1><p>You searched for: ${q}</p></body></html>`);
  }

  // BUG F4 - SQL injection (tautology bypasses the owner filter).
  if (p === "/api/items") {
    const id = url.searchParams.get("id") || "";
    if (/or\s+1\s*=\s*1/i.test(id)) return j(res, 200, { items: ITEMS, note: "filter bypassed" });
    const it = ITEMS.find((x) => String(x.id) === id);
    return it ? j(res, 200, { items: [it] }) : j(res, 200, { items: [] });
  }

  // BUG F5 - open redirect: Location straight from user input.
  if (p === "/go") {
    const next = url.searchParams.get("next") || "/";
    res.writeHead(302, { Location: next });
    return res.end();
  }

  // BUG F6 - path traversal: normalize() alone does not stop `..` escaping the root.
  if (p === "/files") {
    const name = url.searchParams.get("name") || "readme.txt";
    const target = normalize(join("/srv/public", name));
    if (!target.startsWith("/srv/public")) {
      return j(res, 200, { traversal: true, resolved: target, content: "FLAG{traversal}" });
    }
    try {
      return j(res, 200, { content: await readFile(target, "utf8") });
    } catch {
      return j(res, 200, { content: "(fixture file not present)" });
    }
  }

  // BUG F7 - time-based blind: unvalidated delay -> timing oracle.
  if (p === "/api/ping") {
    const delay = Number(url.searchParams.get("delay") || 0);
    const ms = Number.isFinite(delay) && delay > 0 && delay <= 10000 ? delay : 0;
    await new Promise((r) => setTimeout(r, ms));
    return j(res, 200, { pong: true, delayed_ms: ms });
  }

  // BUG F8 - SSRF (loopback-restricted so the fixture cannot be a forwarder).
  if (p === "/fetch") {
    const target = url.searchParams.get("url") || "";
    try {
      const t = new URL(target);
      if (!["127.0.0.1", "localhost", "::1"].includes(t.hostname)) {
        return j(res, 400, { error: "fixture refuses non-loopback targets" });
      }
      const r = await fetch(t, { signal: AbortSignal.timeout(3000) });
      return j(res, 200, { ssrf: true, status: r.status, body: (await r.text()).slice(0, 500) });
    } catch (e) {
      return j(res, 200, { ssrf: true, error: String(e.message || e) });
    }
  }

  // ================================================ L2: second request / identity

  // BUG F9 - IDOR (write): PUT lets anyone overwrite another user's record.
  mt = p.match(/^\/api\/users\/(\d+)$/);
  if (mt && (m === "PUT" || m === "PATCH")) {
    const u = USERS.find((x) => x.id === Number(mt[1]));
    if (!u) return j(res, 404, { error: "not found" });
    try {
      Object.assign(u, JSON.parse((await readBody(req)) || "{}")); // no field allowlist either
    } catch {
      /* ignore */
    }
    return j(res, 200, { updated: u });
  }

  // BUG F10 - mass assignment / privilege escalation: `role` is taken from the body.
  if (p === "/api/profile" && m === "POST") {
    let patch = {};
    try {
      patch = JSON.parse((await readBody(req)) || "{}");
    } catch {
      /* ignore */
    }
    const u = USERS[0];
    Object.assign(u, patch);
    return j(res, 200, { profile: u, isAdmin: u.role === "admin" });
  }

  // BUG F11 - SSTI: template evaluated server-side.
  if (p === "/render") {
    const name = url.searchParams.get("name") || "world";
    const rendered = String(name).replace(/\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}/g, (_, a, b) => String(Number(a) * Number(b)));
    return html(res, 200, `<h1>Hello ${rendered}</h1>`);
  }

  // BUG F12 - JWT alg=none accepted: an unsigned token with role=admin is trusted.
  if (p === "/api/admin/whoami") {
    const token = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    const parts = token.split(".");
    if (parts.length === 3) {
      try {
        const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
        const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
        if (String(header.alg).toLowerCase() === "none") return j(res, 200, { trusted: true, alg: header.alg, payload });
      } catch {
        /* fall through */
      }
    }
    return j(res, 401, { error: "unauthorized" });
  }

  // BUG F13 - NoSQL injection: operator objects reach the matcher.
  // Emulates an extended query parser (qs/express): `q[$ne]=x` arrives as {q: {$ne: 'x'}},
  // so the operator key is `q[$ne]`, NOT `q`. The earlier version read only `get("q")` and
  // was therefore untriggerable -- caught by the fixture's own behaviour test.
  if (p === "/api/search") {
    let operator = "";
    for (const [k] of url.searchParams) {
      const km = k.match(/^q\[\$(\w+)\]$/);
      if (km) operator = `$${km[1]}`;
    }
    if (operator) return j(res, 200, { users: USERS, note: "operator injection", operator });
    const q = url.searchParams.get("q") || "";
    if (q.includes("$ne") || q.includes("[$ne]")) return j(res, 200, { users: USERS, note: "operator injection" });
    return j(res, 200, { users: USERS.filter((u) => u.name === q) });
  }

  // BUG F14 - CORS: arbitrary Origin reflected WITH credentials.
  if (p === "/api/cors-me") {
    const origin = req.headers.origin || "";
    return j(res, 200, { secret: "FLAG{cors_creds}" }, {
      "Access-Control-Allow-Origin": origin || "*",
      "Access-Control-Allow-Credentials": "true",
    });
  }

  // BUG F15 - host header injection: the reset link is built from the Host header.
  if (p === "/forgot-password" && m === "POST") {
    const host = req.headers.host || "localhost";
    return j(res, 200, { sent: true, reset_link: `https://${host}/reset?token=FLAG{host_injection}` });
  }

  // BUG F16 - GraphQL introspection enabled; mutations run unauthenticated.
  if (p === "/graphql") {
    const body = await readBody(req);
    if (body.includes("__schema")) {
      return j(res, 200, { data: { __schema: { types: [{ name: "User" }, { name: "Query" }, { name: "Mutation" }] } } });
    }
    if (body.includes("mutation")) return j(res, 200, { data: { ok: true, note: "mutation executed unauthenticated" } });
    return j(res, 200, { data: { ok: true } });
  }

  // ============================================== L3: chaining / state awareness

  // BUG F17 - race condition: the coupon check and decrement are not atomic.
  if (p === "/api/redeem" && m === "POST") {
    const c = COUPONS[url.searchParams.get("code") || "SAVE10"];
    if (!c) return j(res, 404, { error: "unknown coupon" });
    if (c.remaining <= 0) return j(res, 409, { error: "already used" });
    // Deliberate await between check and decrement -> concurrent requests double-spend.
    await new Promise((r) => setTimeout(r, 40));
    c.remaining -= 1;
    return j(res, 200, { applied: true, discount: c.discount, remaining: c.remaining });
  }

  // BUG F18 - XXE: entity expansion, file access confined to ./fixture-data.
  if (p === "/api/import" && m === "POST") {
    const body = await readBody(req);
    const ent = body.match(/<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"/i);
    if (!ent) return j(res, 200, { expanded: false });
    const sysId = ent[2];
    if (!sysId.startsWith("file://")) return j(res, 200, { expanded: true, note: "external entity resolved" });
    const path = normalize(sysId.replace("file://", ""));
    if (!path.startsWith(DATA_DIR)) {
      return j(res, 400, { error: "fixture refuses entity reads outside fixture-data/", attempted: sysId });
    }
    try {
      return j(res, 200, { expanded: true, entity: ent[1], content: await readFile(path, "utf8") });
    } catch (e) {
      return j(res, 200, { expanded: true, error: e.message });
    }
  }

  // BUG F19 - web cache poisoning / deception: response varies on a param the cache key
  // ignores, and an unkeyed header is reflected back.
  if (p === "/page") {
    return j(res, 200, {
      cached_as: "default",
      variant: url.searchParams.get("cb") || "default",
      reflected_header: req.headers["x-forwarded-host"] || "",
    });
  }

  // ============================================================ benign / traps
  // These exist so false positives are measurable: a tool that flags them is wrong.
  if (p === "/" || p === "/health") return j(res, 200, { ok: true, service: "bughive-eval-fixture" });
  if (p === "/api/version") return j(res, 200, { version: "1.0.0" }); // banner only, not a bug
  if (p === "/login") return html(res, 200, "<form method=POST><input name=user><input name=pass type=password></form>");
  if (p === "/static/app.js") {
    res.writeHead(200, { "Content-Type": "application/javascript" });
    return res.end("console.log('fixture client');");
  }

  return j(res, 404, { error: "not found" });
});

server.listen(PORT, BIND, () => {
  process.stdout.write(
    JSON.stringify({ listening: true, url: `http://${BIND}:${PORT}`, note: "local vulnerable fixture", bugs: 19 }) + "\n"
  );
});
