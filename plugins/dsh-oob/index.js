/**
 * dsh-oob — out-of-band interaction listener.
 *
 * WHY THIS EXISTS
 * A whole family of vulnerabilities only proves itself OUT OF BAND: blind SSRF, blind
 * XXE, blind XSS, log4shell-style JNDI lookups, and any RCE where the response is not
 * reflected. The pipeline had no listener at all -- `recon-15` merely substituted a
 * `BUGHIVE_COLLABORATOR_URL` environment variable if the operator happened to set one,
 * with no minting, no polling and no correlation. So those classes were not "hard to
 * find", they were IMPOSSIBLE to confirm. Public benchmarks show the same shape: agents
 * score near-zero on blind variants (MAPTA: blind SQLi 0%).
 *
 * WHAT THIS DOES
 * Runs a local HTTP listener (and optionally a UDP DNS listener), mints unique
 * per-payload callback URLs, records every inbound interaction, and correlates it back to
 * the token that was planted. That converts "we sent a payload and saw nothing" into
 * "the target's server made a DNS lookup for our token", which is evidence.
 *
 * SAFETY
 * Binds to 127.0.0.1 by default. Reaching the internet requires an operator to bind a
 * public interface or front it with a tunnel, and to supply the externally reachable host
 * in `publicHost`. It never sends traffic to a target itself.
 */

import { createServer } from "node:http";
import { createSocket } from "node:dgram";
import { randomBytes } from "node:crypto";

export const name = "oob";
export const inject = ["tools"];

/** Parse a DNS QNAME out of a raw query packet. Returns null if unparseable. */
export function parseDnsQuestion(buf) {
  try {
    if (buf.length < 12) return null;
    let off = 12;
    const labels = [];
    while (off < buf.length) {
      const len = buf[off];
      if (len === 0) break;
      if ((len & 0xc0) === 0xc0) break; // compression pointer: stop
      off += 1;
      if (off + len > buf.length) return null;
      labels.push(buf.toString("ascii", off, off + len));
      off += len;
    }
    return labels.length ? labels.join(".") : null;
  } catch {
    return null;
  }
}

/** Extract a minted token from a hostname, path, header value or DNS query. */
export function extractToken(text, tokens) {
  if (!text) return null;
  const hay = String(text).toLowerCase();
  for (const t of tokens) {
    if (hay.includes(t.toLowerCase())) return t;
  }
  return null;
}

export function apply(ctx, config = {}) {
  const cfg = {
    bindHost: "127.0.0.1",
    httpPort: 8787,
    dnsPort: 5353,
    enableDns: true,
    publicHost: null, // set to the externally reachable host when tunnelling
    maxInteractions: 2000,
    ...config,
  };

  const state = {
    http: null,
    dns: null,
    tokens: new Map(), // token -> {note, createdAt}
    interactions: [],
    startedAt: null,
  };

  const baseUrl = () => `http://${cfg.publicHost || cfg.bindHost}:${cfg.httpPort}`;
  const dnsDomain = () => `${(cfg.publicHost || cfg.bindHost).replace(/\./g, "-")}.oob.local`;

  function record(kind, data) {
    const entry = { kind, ts: new Date().toISOString(), ...data };
    state.interactions.push(entry);
    if (state.interactions.length > cfg.maxInteractions) {
      state.interactions.splice(0, state.interactions.length - cfg.maxInteractions);
    }
    return entry;
  }

  async function startListener() {
    if (state.http) return;
    state.http = createServer((req, res) => {
      const host = req.headers.host || "";
      const url = req.url || "/";
      const blob = `${host} ${url} ${Object.values(req.headers).join(" ")}`;
      const token = extractToken(blob, [...state.tokens.keys()]);
      record("http", {
        token,
        method: req.method,
        host,
        path: url,
        source_ip: req.socket.remoteAddress,
        headers: req.headers,
      });
      state.http.getConnections?.((err, n) => void 0);
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
    });
    await new Promise((resolve, reject) => {
      state.http.once("error", reject);
      state.http.listen(cfg.httpPort, cfg.bindHost, resolve);
    });

    if (cfg.enableDns) {
      state.dns = createSocket("udp4");
      state.dns.on("message", (msg, rinfo) => {
        const qname = parseDnsQuestion(msg);
        const token = extractToken(qname, [...state.tokens.keys()]);
        record("dns", { token, qname, source_ip: rinfo.address, bytes: msg.length });
        // Reply REFUSED (0x8005) so resolvers stop quickly; we only need the lookup itself.
        try {
          const reply = Buffer.from(msg.subarray(0, 12));
          reply.writeUInt16BE(0x8005, 2);
          state.dns.send(reply, rinfo.port, rinfo.address);
        } catch {
          /* best effort */
        }
      });
      await new Promise((resolve, reject) => {
        state.dns.once("error", reject);
        state.dns.bind(cfg.dnsPort, cfg.bindHost, resolve);
      });
    }
    state.startedAt = new Date().toISOString();
  }

  async function stopListener() {
    if (state.http) {
      await new Promise((r) => state.http.close(r));
      state.http = null;
    }
    if (state.dns) {
      await new Promise((r) => state.dns.close(r));
      state.dns = null;
    }
  }

  ctx.tools.register({
    name: "oob_start",
    description:
      "Start the out-of-band interaction listener (HTTP + optional UDP DNS). Idempotent. Loopback by default; set publicHost/bindHost to receive callbacks from a remote target.",
    parameters: {
      type: "object",
      properties: {
        bindHost: { type: "string", description: "Interface to bind (default 127.0.0.1)." },
        httpPort: { type: "number" },
        dnsPort: { type: "number" },
        enableDns: { type: "boolean" },
        publicHost: { type: "string", description: "Externally reachable host to embed in minted URLs." },
      },
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      if (args.bindHost) cfg.bindHost = args.bindHost;
      if (Number.isFinite(args.httpPort)) cfg.httpPort = args.httpPort;
      if (Number.isFinite(args.dnsPort)) cfg.dnsPort = args.dnsPort;
      if (typeof args.enableDns === "boolean") cfg.enableDns = args.enableDns;
      if (args.publicHost) cfg.publicHost = args.publicHost;
      await startListener();
      return JSON.stringify({
        started: true,
        http: baseUrl(),
        dns: state.dns ? `${cfg.bindHost}:${cfg.dnsPort}` : null,
        note:
          cfg.publicHost
            ? "publicHost set: minted URLs are externally routable."
            : "loopback only: only tests originating on this host can trigger a callback. Set publicHost (with a tunnel or public bind) for remote targets.",
      });
    },
  });

  ctx.tools.register({
    name: "oob_mint",
    description:
      "Mint a unique callback token and its URLs. Plant the returned url/dnsName in the payload under test (SSRF parameter, XXE SYSTEM entity, JNDI string, XSS payload), then use oob_wait to confirm.",
    parameters: {
      type: "object",
      properties: { note: { type: "string", description: "What this token is being planted in." } },
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      await startListener();
      const token = randomBytes(8).toString("hex");
      state.tokens.set(token, { note: args.note || "", createdAt: new Date().toISOString() });
      return JSON.stringify({
        token,
        note: args.note || "",
        url: `${baseUrl()}/${token}`,
        urlHostOnly: `${cfg.publicHost || cfg.bindHost}`,
        dnsName: state.dns ? `${token}.${dnsDomain()}` : null,
      });
    },
  });

  ctx.tools.register({
    name: "oob_poll",
    description:
      "Return recorded out-of-band interactions, newest last. Optionally filter to a single token. An empty result means no callback arrived.",
    parameters: {
      type: "object",
      properties: {
        token: { type: "string", description: "Optional: only interactions matching this token." },
        since: { type: "string", description: "Optional ISO timestamp lower bound." },
      },
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      let items = state.interactions;
      if (args.token) items = items.filter((i) => i.token === args.token);
      if (args.since) items = items.filter((i) => i.ts > args.since);
      return JSON.stringify({
        listening: !!state.http,
        started_at: state.startedAt,
        total_recorded: state.interactions.length,
        matching: items.length,
        interactions: items.slice(-100),
      });
    },
  });

  ctx.tools.register({
    name: "oob_wait",
    description:
      "Wait up to timeoutMs for an interaction with the given token. This is the confirmation primitive for blind classes: a callback is proof the target's server (or browser) processed the payload. Returns as soon as the FIRST matching interaction arrives — if a payload can trigger several kinds (e.g. HTTP and DNS), mint one token per vector or use oob_poll afterwards to see them all.",
    parameters: {
      type: "object",
      properties: {
        token: { type: "string", description: "Token from oob_mint." },
        timeoutMs: { type: "number", description: "How long to wait (default 15000)." },
        pollMs: { type: "number", description: "Poll interval (default 500)." },
      },
      required: ["token"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const timeoutMs = Number.isFinite(args.timeoutMs) ? args.timeoutMs : 15000;
      const pollMs = Number.isFinite(args.pollMs) ? args.pollMs : 500;
      const deadline = Date.now() + timeoutMs;
      const found = [];
      while (Date.now() < deadline) {
        const hits = state.interactions.filter((i) => i.token === args.token);
        if (hits.length) {
          found.push(...hits);
          break;
        }
        await new Promise((r) => setTimeout(r, pollMs));
      }
      const kinds = [...new Set(found.map((f) => f.kind))];
      return JSON.stringify({
        token: args.token,
        confirmed: found.length > 0,
        interaction_count: found.length,
        kinds,
        interactions: found.slice(-20),
        verdict:
          found.length > 0
            ? `CONFIRMED out-of-band interaction (${kinds.join("+")}) — the payload was processed.`
            : "No interaction within the timeout. Not confirmed; do NOT report.",
      });
    },
  });

  ctx.tools.register({
    name: "oob_stop",
    description: "Stop the listener and return a summary of everything it captured.",
    parameters: { type: "object", properties: {} },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute() {
      const summary = {
        tokens_minted: state.tokens.size,
        interactions: state.interactions.length,
        by_kind: state.interactions.reduce((a, i) => ((a[i.kind] = (a[i.kind] || 0) + 1), a), {}),
      };
      await stopListener();
      return JSON.stringify({ stopped: true, ...summary });
    },
  });

  console.log("[oob] registered: oob_start, oob_mint, oob_poll, oob_wait, oob_stop");
}
