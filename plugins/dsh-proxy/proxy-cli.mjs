#!/usr/bin/env node
/**
 * proxy-cli.mjs — drive the capture proxy from bash.
 *
 * Why this exists: the agent can call the plugin tools, but a bash recon step cannot. A
 * live proxy that only the agent can start is useless for capturing what shell commands
 * do, which is exactly the traffic that was missing from the journal.
 *
 *   node proxy-cli.mjs serve --port 8899 --log /path/capture.jsonl [--mitm]
 *   node proxy-cli.mjs requests --log /path/capture.jsonl [--host H] [--limit N]
 *   node proxy-cli.mjs ca
 */
import { apply, ensureCa, leafFor } from "./index.js";

const argv = process.argv.slice(2);
const cmd = argv[0] || "help";
const flag = (name, dflt = null) => {
  const i = argv.indexOf(`--${name}`);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : dflt;
};
const has = (name) => argv.includes(`--${name}`);

const logPath = flag("log", "/tmp/bughive-proxy.jsonl");
const port = Number(flag("port", "8899"));
const bindHost = flag("bind", "127.0.0.1");
const mitm = has("mitm");

if (cmd === "serve") {
  const registry = new Map();
  const ctx = { tools: { register: (d) => registry.set(d.name, d) }, on() {}, emit() {}, get() {} };
  const origLog = console.log;
  console.log = () => {};
  apply(ctx, { port, bindHost, mitm, logPath });
  console.log = origLog;

  const started = JSON.parse(
    await registry.get("proxy_start").execute({ port, bindHost, mitm })
  );
  if (!started.started) {
    process.stderr.write(`proxy-cli: failed to start: ${started.error}\n`);
    process.exit(1);
  }
  process.stdout.write(JSON.stringify(started) + "\n");

  const shutdown = async () => {
    try {
      await registry.get("proxy_stop").execute({});
    } catch {
      /* ignore */
    }
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
} else if (cmd === "requests") {
  // Read the capture file directly; no need to attach to the running proxy.
  const fs = await import("node:fs");
  if (!fs.existsSync(logPath)) {
    process.stdout.write(JSON.stringify({ count: 0, requests: [], note: "no captures yet" }) + "\n");
    process.exit(0);
  }
  const host = flag("host");
  const limit = Number(flag("limit", "100"));
  const items = [];
  for (const line of fs.readFileSync(logPath, "utf8").split("\n")) {
    const t = line.trim();
    if (!t) continue;
    try {
      const o = JSON.parse(t);
      if (host && !String(o.host || "").includes(host)) continue;
      items.push(o);
    } catch {
      /* skip malformed */
    }
  }
  process.stdout.write(
    JSON.stringify({ count: items.length, requests: items.slice(-limit) }) + "\n"
  );
} else if (cmd === "ca") {
  try {
    const ca = ensureCa();
    void leafFor;
    process.stdout.write(JSON.stringify({ ca_cert: ca.crt, created: ca.created }) + "\n");
  } catch (e) {
    process.stdout.write(JSON.stringify({ error: e.message }) + "\n");
    process.exit(1);
  }
} else {
  process.stdout.write("usage: proxy-cli.mjs serve|requests|ca [--port N] [--log FILE] [--mitm] [--host H]\n");
  process.exit(2);
}
