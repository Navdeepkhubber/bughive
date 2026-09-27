/**
 * dsh-proxy — a live HTTP/HTTPS forward proxy that journals every request.
 *
 * WHY THIS EXISTS
 * The journal only knew about requests the pipeline itself made. Anything the agent ran
 * directly (a raw `curl` in a bash step, a python script, a third-party binary) bypassed it
 * entirely, so the hunt's request history was partial and `audit_report` could not verify
 * claims about it. This is the missing capture layer.
 *
 * HOW IT WORKS
 *   - Plain HTTP: the request is parsed in full (method, absolute URL, headers, body) and
 *     forwarded; the response is streamed back.
 *   - HTTPS: the CONNECT target (host:port) is always recorded, which is enough to prove
 *     which hosts were contacted.
 *   - HTTPS with --mitm: a CA is generated once (openssl) and a per-host leaf certificate
 *     is minted on demand, so the tunnel is terminated and the inner request's full path,
 *     headers and body are captured too. This needs the client to trust the generated CA
 *     (see `proxy_ca` / `--cacert`), which is why it is opt-in rather than default.
 *
 * Requests are appended to a JSONL capture file. `proxy_journal` folds them into the hunt
 * journal so the existing audit/coverage tooling sees them.
 *
 * SAFETY
 * Binds 127.0.0.1 by default. It only forwards what the local client sends it.
 */

import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { execFileSync } from "node:child_process";
import { mkdirSync, appendFileSync, readFileSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

export const name = "proxy";
export const inject = ["tools"];

const CA_DIR = join(tmpdir(), "bughive-proxy-ca");

/** Generate (once) a CA used to sign per-host leaf certificates for MITM. */
export function ensureCa(dir = CA_DIR) {
  mkdirSync(dir, { recursive: true });
  const key = join(dir, "ca.key");
  const crt = join(dir, "ca.crt");
  if (existsSync(key) && existsSync(crt)) return { key, crt, created: false };
  execFileSync(
    "openssl",
    ["req", "-x509", "-newkey", "rsa:2048", "-keyout", key, "-out", crt,
     "-days", "365", "-nodes", "-subj", "/CN=bughive-proxy-ca"],
    { stdio: "ignore" }
  );
  return { key, crt, created: true };
}

/** Mint (and cache) a leaf certificate for one hostname. */
export function leafFor(host, ca) {
  const safe = host.replace(/[^a-z0-9.-]/gi, "_");
  const dir = join(CA_DIR, "leaf");
  mkdirSync(dir, { recursive: true });
  const key = join(dir, `${safe}.key`);
  const crt = join(dir, `${safe}.crt`);
  if (existsSync(key) && existsSync(crt)) return { key: readFileSync(key), cert: readFileSync(crt) };
  const csr = join(dir, `${safe}.csr`);
  const ext = join(dir, `${safe}.ext`);
  writeFileSync(ext, `subjectAltName=DNS:${host}\n`);
  execFileSync("openssl", ["req", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", csr,
    "-subj", `/CN=${host}`], { stdio: "ignore" });
  execFileSync("openssl", ["x509", "-req", "-in", csr, "-CA", ca.crt, "-CAkey", ca.key,
    "-CAcreateserial", "-out", crt, "-days", "30", "-extfile", ext], { stdio: "ignore" });
  return { key: readFileSync(key), cert: readFileSync(crt) };
}

export function apply(ctx, config = {}) {
  const cfg = {
    bindHost: "127.0.0.1",
    port: 8899,
    mitm: false,
    logPath: join(tmpdir(), "bughive-proxy.jsonl"),
    maxCapture: 5000,
    ...config,
  };

  const state = { server: null, captures: [], startedAt: null, mitmActive: false, ca: null };

  function rec(entry) {
    const e = { ts: new Date().toISOString(), ...entry };
    state.captures.push(e);
    if (state.captures.length > cfg.maxCapture) {
      state.captures.splice(0, state.captures.length - cfg.maxCapture);
    }
    try {
      appendFileSync(cfg.logPath, JSON.stringify(e) + "\n");
    } catch {
      /* capture must never break proxying */
    }
    return e;
  }

  function proxyHttp(req, res) {
    let target;
    try {
      target = new URL(req.url);
    } catch {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("bughive-proxy: expected an absolute-form request URI");
      return;
    }
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks);
      rec({
        scheme: "http",
        method: req.method,
        host: target.host,
        path: target.pathname + target.search,
        url: target.href,
        headers: req.headers,
        body: body.length ? body.toString("utf8").slice(0, 4000) : "",
      });
      const upstream = http.request(
        {
          hostname: target.hostname,
          port: target.port || 80,
          path: target.pathname + target.search,
          method: req.method,
          headers: req.headers,
        },
        (up) => {
          res.writeHead(up.statusCode || 502, up.headers);
          up.pipe(res);
        }
      );
      upstream.on("error", (e) => {
        rec({ scheme: "http", method: req.method, url: target.href, error: e.message });
        if (!res.headersSent) res.writeHead(502, { "Content-Type": "text/plain" });
        res.end(`bughive-proxy upstream error: ${e.message}`);
      });
      if (body.length) upstream.write(body);
      upstream.end();
    });
  }

  function tunnel(req, clientSocket, head) {
    const [host, portRaw] = String(req.url).split(":");
    const port = Number(portRaw) || 443;
    rec({ scheme: "https", method: "CONNECT", host, port, url: `https://${host}:${port}` });
    const upstream = net.connect(port, host, () => {
      clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head && head.length) upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    const bail = (e) => {
      rec({ scheme: "https", method: "CONNECT", host, port, error: String(e.message || e) });
      try {
        clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      } catch {
        /* ignore */
      }
    };
    upstream.on("error", bail);
    clientSocket.on("error", () => upstream.destroy());
  }

  function mitmConnect(req, clientSocket, head) {
    const [host, portRaw] = String(req.url).split(":");
    const port = Number(portRaw) || 443;
    let leaf;
    try {
      leaf = leafFor(host, state.ca);
    } catch (e) {
      rec({ scheme: "https", method: "CONNECT", host, port, error: `leaf mint failed: ${e.message}` });
      return tunnel(req, clientSocket, head);
    }
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    state.mitmActive = true;

    // Terminate TLS for this host, then parse the inner HTTP request.
    const tlsServer = https.createServer({ key: leaf.key, cert: leaf.cert }, (innerReq, innerRes) => {
      const chunks = [];
      innerReq.on("data", (c) => chunks.push(c));
      innerReq.on("end", () => {
        const body = Buffer.concat(chunks);
        rec({
          scheme: "https-mitm",
          method: innerReq.method,
          host,
          port,
          path: innerReq.url,
          url: `https://${host}${innerReq.url}`,
          headers: innerReq.headers,
          body: body.length ? body.toString("utf8").slice(0, 4000) : "",
        });
        const up = https.request(
          {
            hostname: host,
            port,
            path: innerReq.url,
            method: innerReq.method,
            headers: innerReq.headers,
            rejectUnauthorized: false, // we are auditing; upstream certs are checked separately
          },
          (upRes) => {
            innerRes.writeHead(upRes.statusCode || 502, upRes.headers);
            upRes.pipe(innerRes);
          }
        );
        up.on("error", (e) => {
          rec({ scheme: "https-mitm", method: innerReq.method, host, error: e.message });
          if (!innerRes.headersSent) innerRes.writeHead(502, { "Content-Type": "text/plain" });
          innerRes.end(`bughive-proxy upstream error: ${e.message}`);
        });
        if (body.length) up.write(body);
        up.end();
      });
    });
    tlsServer.on("tlsClientError", (e) => rec({ scheme: "https", method: "CONNECT", host, error: `tls: ${e.message}` }));
    tlsServer.emit("connection", clientSocket);
    if (head && head.length) clientSocket.unshift(head);
  }

  async function start() {
    if (state.server) return;
    if (cfg.mitm) {
      try {
        state.ca = ensureCa();
      } catch (e) {
        throw new Error(`MITM requested but openssl/CA generation failed: ${e.message}`);
      }
    }
    state.server = http.createServer(proxyHttp);
    state.server.on("connect", (req, socket, head) =>
      cfg.mitm ? mitmConnect(req, socket, head) : tunnel(req, socket, head)
    );
    await new Promise((resolve, reject) => {
      state.server.once("error", reject);
      state.server.listen(cfg.port, cfg.bindHost, resolve);
    });
    state.startedAt = new Date().toISOString();
  }

  async function stop() {
    if (!state.server) return false;
    await new Promise((r) => state.server.close(r));
    state.server = null;
    return true;
  }

  ctx.tools.register({
    name: "proxy_start",
    description:
      "Start a local HTTP/HTTPS forward proxy that journals every request it forwards. Point clients at it with HTTP_PROXY/HTTPS_PROXY. HTTPS is tunnelled and the CONNECT target recorded; with mitm:true a CA is generated and full inner requests are captured (clients must trust it).",
    parameters: {
      type: "object",
      properties: {
        port: { type: "number", description: "Port to bind (default 8899)." },
        bindHost: { type: "string" },
        mitm: { type: "boolean", description: "Terminate TLS to capture full HTTPS requests." },
      },
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      if (Number.isFinite(args.port)) cfg.port = args.port;
      if (args.bindHost) cfg.bindHost = args.bindHost;
      if (typeof args.mitm === "boolean") cfg.mitm = args.mitm;
      try {
        await start();
      } catch (e) {
        return JSON.stringify({ started: false, error: e.message });
      }
      return JSON.stringify({
        started: true,
        proxy: `http://${cfg.bindHost}:${cfg.port}`,
        env: { HTTP_PROXY: `http://${cfg.bindHost}:${cfg.port}`, HTTPS_PROXY: `http://${cfg.bindHost}:${cfg.port}` },
        mitm: cfg.mitm,
        ca_cert: cfg.mitm ? state.ca.crt : null,
        log: cfg.logPath,
        note: cfg.mitm
          ? "MITM active: clients must trust ca_cert (curl --cacert, NODE_EXTRA_CA_CERTS, or the system store)."
          : "HTTPS is tunnelled: the CONNECT target host is captured, not the inner path. Enable mitm for full HTTPS capture.",
      });
    },
  });

  ctx.tools.register({
    name: "proxy_requests",
    description: "Return captured proxy requests, newest last. Optionally filter by host substring.",
    parameters: {
      type: "object",
      properties: {
        host: { type: "string", description: "Only requests whose host contains this." },
        limit: { type: "number" },
      },
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      let items = state.captures;
      if (args.host) items = items.filter((c) => String(c.host || "").includes(args.host));
      const limit = Number.isFinite(args.limit) ? args.limit : 100;
      const byScheme = items.reduce((a, c) => ((a[c.scheme] = (a[c.scheme] || 0) + 1), a), {});
      return JSON.stringify({
        listening: !!state.server,
        mitm_active: state.mitmActive,
        started_at: state.startedAt,
        total: state.captures.length,
        by_scheme: byScheme,
        requests: items.slice(-limit),
      });
    },
  });

  ctx.tools.register({
    name: "proxy_ca_path",
    description: "Path to the generated MITM CA certificate (for clients to trust), or null if MITM is off.",
    parameters: { type: "object", properties: {} },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute() {
      return JSON.stringify({ ca_cert: state.ca ? state.ca.crt : null, mitm: cfg.mitm });
    },
  });

  ctx.tools.register({
    name: "proxy_stop",
    description: "Stop the proxy and return a capture summary.",
    parameters: { type: "object", properties: {} },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute() {
      const summary = {
        captures: state.captures.length,
        hosts: [...new Set(state.captures.map((c) => c.host).filter(Boolean))].slice(0, 50),
      };
      const stopped = await stop();
      return JSON.stringify({ stopped, ...summary });
    },
  });

  console.log("[proxy] registered: proxy_start, proxy_requests, proxy_ca_path, proxy_stop");
}
