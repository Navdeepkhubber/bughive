#!/usr/bin/env node
/**
 * CLI wrapper around the dsh-oob listener so the BASH recon pipeline can use the same
 * capability as the plugin. Without this, recon-15 needs an operator-supplied
 * BUGHIVE_COLLABORATOR_URL and blind classes are simply not testable.
 *
 * Usage:
 *   node oob-cli.mjs serve --port 8787 [--dns-port 5353] [--log /path/oob.jsonl]
 *   node oob-cli.mjs poll  --log /path/oob.jsonl [--token TOKEN] [--format json|urls]
 *   node oob-cli.mjs tokens --log /path/oob.jsonl
 *
 * `serve` runs in the foreground (background it with `&` from bash) and appends one JSON
 * line per interaction. Loopback-only by default: a loopback collaborator catches SSRF that
 * reaches 127.0.0.1 (internal services, cloud metadata via a local proxy, etc.). To catch
 * callbacks from a remote target, bind a public interface or front it with a tunnel and
 * pass --public-host.
 */
import { createServer } from "node:http";
import { createSocket } from "node:dgram";
import { randomBytes } from "node:crypto";
import { appendFileSync, readFileSync, existsSync, writeFileSync } from "node:fs";

const argv = process.argv.slice(2);
const cmd = argv[0] || "help";
const flag = (name, dflt = null) => {
  const i = argv.indexOf(`--${name}`);
  return i !== -1 && argv[i + 1] ? argv[i + 1] : dflt;
};

const logPath = flag("log", "/tmp/bughive-oob.jsonl");
const bindHost = flag("bind", "127.0.0.1");
const httpPort = Number(flag("port", "8787"));
const dnsPort = Number(flag("dns-port", "5353"));
const publicHost = flag("public-host", bindHost);

function parseDnsQuestion(buf) {
  try {
    if (buf.length < 12) return null;
    let off = 12;
    const labels = [];
    while (off < buf.length) {
      const len = buf[off];
      if (len === 0) break;
      if ((len & 0xc0) === 0xc0) break;
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

if (cmd === "serve") {
  writeFileSync(logPath, "");
  const token = randomBytes(8).toString("hex");
  const record = (obj) => appendFileSync(logPath, JSON.stringify(obj) + "\n");

  const http = createServer((req, res) => {
    record({
      kind: "http",
      ts: new Date().toISOString(),
      method: req.method,
      host: req.headers.host || "",
      path: req.url || "/",
      source_ip: req.socket.remoteAddress,
    });
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
  });
  http.listen(httpPort, bindHost, () => {
    process.stdout.write(
      JSON.stringify({
        serving: true,
        url: `http://${publicHost}:${httpPort}`,
        sample_path: `/${token}`,
        log: logPath,
      }) + "\n"
    );
  });

  let dns = null;
  if (flag("no-dns") === null) {
    try {
      dns = createSocket("udp4");
      dns.on("message", (msg, rinfo) => {
        record({
          kind: "dns",
          ts: new Date().toISOString(),
          qname: parseDnsQuestion(msg),
          source_ip: rinfo.address,
        });
        try {
          const reply = Buffer.from(msg.subarray(0, 12));
          reply.writeUInt16BE(0x8005, 2);
          dns.send(reply, rinfo.port, rinfo.address);
        } catch {
          /* best effort */
        }
      });
      dns.bind(dnsPort, bindHost);
    } catch {
      dns = null;
    }
  }

  const shutdown = () => {
    try {
      http.close();
    } catch {
      /* ignore */
    }
    try {
      if (dns) dns.close();
    } catch {
      /* ignore */
    }
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
} else if (cmd === "poll") {
  if (!existsSync(logPath)) {
    process.stdout.write(JSON.stringify({ interactions: [], count: 0, note: "no log yet" }) + "\n");
    process.exit(0);
  }
  const token = flag("token");
  const fmt = flag("format", "json");
  const lines = readFileSync(logPath, "utf8").split("\n").filter((l) => l.trim());
  const items = [];
  for (const l of lines) {
    try {
      const o = JSON.parse(l);
      if (token && !`${o.path || ""} ${o.host || ""} ${o.qname || ""}`.includes(token)) continue;
      items.push(o);
    } catch {
      /* skip malformed */
    }
  }
  if (fmt === "urls") {
    for (const i of items) process.stdout.write(`${i.kind}\t${i.path || i.qname || ""}\t${i.source_ip || ""}\n`);
  } else {
    process.stdout.write(JSON.stringify({ count: items.length, interactions: items.slice(-200) }) + "\n");
  }
} else if (cmd === "tokens") {
  const token = randomBytes(8).toString("hex");
  process.stdout.write(
    JSON.stringify({
      token,
      url: `http://${publicHost}:${httpPort}/${token}`,
      dns_name: `${token}.oob.local`,
    }) + "\n"
  );
} else {
  process.stdout.write(
    "usage: oob-cli.mjs serve|poll|tokens [--port N] [--dns-port N] [--log FILE] [--token T] [--public-host H] [--bind H]\n"
  );
  process.exit(2);
}
