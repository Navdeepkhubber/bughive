import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { execFile, execFileSync } from "node:child_process";
import { mkdtemp, mkdir, writeFile, readFile, rm, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

import { apply as applyOob, listenLoopback } from "../plugins/dsh-oob/index.js";
import {
  assertSelfHostedCollaborator,
  InteractshClient,
  sealInteractions,
} from "../plugins/dsh-oob/interactsh.js";
import { apply as applyValidators } from "../plugins/dsh-validators/index.js";
import { buildExecutor } from "../scripts/pipeline/jev-decide.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/**
 * Loopback stand-in for a self-hosted Interactsh HTTP API.
 * Interactions are appended only when a request actually arrives.
 */
function startMockInteractsh({ requireToken = "" } = {}) {
  const sessions = new Map();
  const contacted = [];
  const server = createServer(async (req, res) => {
    const host = req.headers.host || "";
    contacted.push({ host, url: req.url || "/", method: req.method, authorization: req.headers.authorization || "" });
    const url = new URL(req.url || "/", "http://127.0.0.1");
    const send = (code, obj) => {
      const body = JSON.stringify(obj);
      res.writeHead(code, { "Content-Type": "application/json" });
      res.end(body);
    };
    if (requireToken && req.headers.authorization !== requireToken && (url.pathname === "/register" || url.pathname === "/poll" || url.pathname === "/deregister")) {
      res.writeHead(401);
      res.end("");
      return;
    }
    if (req.method === "POST" && url.pathname === "/register") {
      const body = JSON.parse(await readBody(req));
      const id = body["correlation-id"];
      const aesKey = randomBytes(32);
      sessions.set(id, {
        secret: body["secret-key"],
        publicKey: body["public-key"],
        aesKey,
        events: [],
      });
      send(200, { message: "registration successful" });
      return;
    }
    if (req.method === "GET" && url.pathname === "/poll") {
      const id = url.searchParams.get("id");
      const secret = url.searchParams.get("secret");
      const session = sessions.get(id);
      if (!session || session.secret !== secret) {
        send(400, { error: "could not get interactions: correlation-id provided does not exist" });
        return;
      }
      send(200, sealInteractions(session.publicKey, session.aesKey, session.events));
      return;
    }
    if (req.method === "POST" && url.pathname === "/deregister") {
      const body = JSON.parse(await readBody(req) || "{}");
      const session = sessions.get(body["correlation-id"]);
      if (!session || session.secret !== body["secret-key"]) {
        send(400, { error: "could not remove id" });
        return;
      }
      sessions.delete(body["correlation-id"]);
      send(200, { message: "deregistration successful" });
      return;
    }
    const blob = `${host} ${url.pathname}`;
    for (const [id, session] of sessions) {
      if (!blob.includes(id)) continue;
      const protocol = url.pathname.startsWith("/smtp/") ? "smtp" : "http";
      session.events.push({
        protocol,
        "unique-id": id,
        "full-id": url.pathname,
        "remote-address": req.socket.remoteAddress || "127.0.0.1",
        timestamp: new Date().toISOString(),
        "raw-request": `${req.method} ${req.url}`,
      });
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
      return;
    }
    res.writeHead(404);
    res.end("no session");
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        url: `http://127.0.0.1:${port}/`,
        port,
        contacted,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

test("collaborator guard refuses public oast and ProjectDiscovery Cloud before any request", () => {
  const calls = [];
  const fetchImpl = async () => {
    calls.push("fetch");
    throw new Error("fetch must not run");
  };
  for (const raw of [
    "https://oast.pro",
    "https://oast.live",
    "https://oast.site",
    "https://oast.online",
    "https://oast.fun",
    "https://oast.me",
    "http://evil.oast.pro/register",
    "https://api.projectdiscovery.io",
    "https://cloud.projectdiscovery.io/v1/user",
    "oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me",
    "https://oast.pro,https://oast.live",
  ]) {
    assert.throws(() => assertSelfHostedCollaborator(raw), /public OAST|ProjectDiscovery|comma/i, raw);
  }
  assert.throws(
    () => new InteractshClient({ serverUrl: "https://oast.pro", fetchImpl }),
    /public OAST|ProjectDiscovery/i
  );
  assert.equal(calls.length, 0);
  const allowed = assertSelfHostedCollaborator("http://127.0.0.1:9/oob-canary");
  assert.equal(allowed.hostname, "127.0.0.1");
  assert.equal(allowed.serverRoot, false);

  const cli = (args) => {
    try {
      const stdout = execFileSync(process.execPath, ["plugins/dsh-oob/oob-cli.mjs", ...args], {
        cwd: ROOT,
        encoding: "utf8",
      });
      return { status: 0, stdout };
    } catch (error) {
      return { status: error.status, stdout: error.stdout?.toString() || "" };
    }
  };
  const refused = cli(["guard", "--server", "https://oast.pro"]);
  assert.notEqual(refused.status, 0);
  assert.equal(JSON.parse(refused.stdout).allowed, false);
  const cloud = cli(["guard", "--server", "https://api.projectdiscovery.io"]);
  assert.equal(JSON.parse(cloud.stdout).allowed, false);
  const legacy = cli(["guard", "--server", "http://127.0.0.1:9/oob-canary"]);
  assert.equal(legacy.status, 0);
  assert.equal(JSON.parse(legacy.stdout).allowed, true);
});

test("interactsh adapter registers, polls a real callback, resumes, and deregisters on 127.0.0.1", async () => {
  const mock = await startMockInteractsh({ requireToken: "lab-token" });
  const hosts = new Set();
  const fetchImpl = async (url, init) => {
    const u = new URL(url);
    hosts.add(u.hostname);
    assert.equal(u.hostname, "127.0.0.1");
    assert.equal(u.port, String(mock.port));
    return fetch(url, init);
  };
  const logPath = join(tmpdir(), `bh-oob-${mock.port}.jsonl`);
  const client = new InteractshClient({
    serverUrl: mock.url,
    token: "lab-token",
    fetchImpl,
    logPath,
  });
  try {
    await client.register();
    const planted = client.mintPayload();
    assert.equal(planted.token, client.correlationId);
    assert.match(planted.url, /^http:\/\/127\.0\.0\.1:\d+\//);
    assert.ok(planted.url.includes(planted.token));

    const empty = await client.poll();
    assert.deepEqual(empty, []);

    const missed = await fetch(planted.url.replace(planted.token, "not-the-token"));
    assert.equal(missed.status, 404);
    assert.deepEqual(await client.poll(), []);

    const hit = await fetch(planted.url);
    assert.equal(hit.status, 200);
    const interactions = await client.poll();
    assert.equal(interactions.length, 1);
    assert.equal(interactions[0].token, planted.token);
    assert.equal(interactions[0].kind, "http");
    assert.equal(interactions[0].recorded, true);
    assert.match(interactions[0].source_ip, /127\.0\.0\.1/);

    const lines = (await readFile(logPath, "utf8")).trim().split("\n");
    assert.equal(lines.length, 1);
    assert.equal(JSON.parse(lines[0]).token, planted.token);

    const resumed = InteractshClient.resume(client.session(), { fetchImpl, logPath });
    const again = await resumed.poll();
    assert.equal(again.length, 1);
    assert.equal(again[0].kind, "http");

    await resumed.deregister();
    await assert.rejects(() => resumed.poll(), /poll/i);
    assert.deepEqual([...hosts], ["127.0.0.1"]);
    assert.equal(mock.contacted.some((c) => /projectdiscovery|oast\./i.test(c.host + c.url)), false);
    assert.ok(mock.contacted.some((c) => c.authorization === "lab-token"));
  } finally {
    await mock.close();
    await rm(logPath, { force: true });
  }
});

test("prove gate polls the collaborator and will not confirm a single or fabricated signal", async () => {
  const exec = buildExecutor({ next_action: "prove" }, "app.example");
  assert.equal(exec.plugin, "validate_by_class");
  assert.equal(exec.repro_route, "execute_repro");
  assert.match(exec.plugin_note, /execute_repro/);
  assert.match(exec.plugin_note, /inconclusive/);
  assert.match(exec.plugin_note, /oob_mint|Interactsh|BUGHIVE_COLLABORATOR_URL/);
  assert.match(exec.plugin_note, /two independent/);

  const tools = new Map();
  applyValidators({ tools: { register: (tool) => tools.set(tool.name, tool) } });
  const router = tools.get("validate_by_class");

  const dnsOnly = JSON.parse(await router.execute({
    bugClass: "ssrf",
    spec: JSON.stringify({
      token: "abcabcabcabcabcabcab",
      interactions: [{ token: "abcabcabcabcabcabcab", kind: "dns", source_ip: "203.0.113.5" }],
    }),
  }));
  assert.equal(dnsOnly.route, "validate_oob");
  assert.equal(dnsOnly.validated, false);
  assert.equal(dnsOnly.disposition, "lead");
  assert.equal(dnsOnly.signal_gate.tag, "standalone_invalid");
  assert.equal(dnsOnly.interaction_recorded, true);

  const dnsPlusHttp = JSON.parse(await router.execute({
    bugClass: "ssrf",
    spec: JSON.stringify({
      token: "abcabcabcabcabcabcab",
      interactions: [
        { token: "abcabcabcabcabcabcab", kind: "dns", source_ip: "203.0.113.5" },
        { token: "abcabcabcabcabcabcab", kind: "http", source_ip: "203.0.113.5" },
      ],
    }),
  }));
  assert.equal(dnsPlusHttp.validated, false);
  assert.equal(dnsPlusHttp.disposition, "lead");
  assert.match(dnsPlusHttp.signal_gate.reason, /two independent/);

  const oneHttp = JSON.parse(await router.execute({
    bugClass: "blind-ssrf",
    spec: JSON.stringify({
      token: "abcabcabcabcabcabcab",
      interactions: [{ token: "abcabcabcabcabcabcab", kind: "http", source_ip: "203.0.113.5" }],
    }),
  }));
  assert.equal(oneHttp.validated, false);
  assert.equal(oneHttp.disposition, "lead");
  assert.match(oneHttp.signal_gate.reason, /two independent/);

  const two = JSON.parse(await router.execute({
    bugClass: "ssrf",
    spec: JSON.stringify({
      token: "abcabcabcabcabcabcab",
      interactions: [
        { token: "abcabcabcabcabcabcab", kind: "http", source_ip: "203.0.113.5" },
        { token: "abcabcabcabcabcabcab", kind: "smtp", source_ip: "203.0.113.5" },
      ],
    }),
  }));
  assert.equal(two.validated, true);
  assert.equal(two.disposition, "confirm");

  const withSecond = JSON.parse(await router.execute({
    bugClass: "xxe",
    spec: JSON.stringify({
      token: "abcabcabcabcabcabcab",
      interactions: [{ token: "abcabcabcabcabcabcab", kind: "http" }],
      secondSignal: { mode: "response-diff", validated: true },
    }),
  }));
  assert.equal(withSecond.validated, true);
  assert.equal(withSecond.disposition, "confirm");

  const mock = await startMockInteractsh();
  const pluginTools = new Map();
  applyOob({ tools: { register: (tool) => pluginTools.set(tool.name, tool) } }, { enableDns: false });
  try {
    const minted = JSON.parse(await pluginTools.get("oob_mint").execute({
      serverUrl: mock.url,
      note: "ssrf param",
    }));
    assert.equal(minted.collaborator, "interactsh");
    assert.ok(minted.session?.correlationId);

    const forged = JSON.parse(await router.execute({
      bugClass: "ssrf",
      spec: JSON.stringify({
        token: minted.token,
        session: minted.session,
        interactions: [{ token: minted.token, kind: "http", source_ip: "203.0.113.9", recorded: true }, { token: minted.token, kind: "smtp", recorded: true }],
      }),
    }));
    assert.equal(forged.validated, false);
    assert.equal(forged.interaction_recorded, false);
    assert.equal(forged.evidence.interaction_count, 0);

    const quiet = JSON.parse(await pluginTools.get("oob_wait").execute({
      token: minted.token,
      timeoutMs: 300,
      pollMs: 50,
    }));
    assert.equal(quiet.confirmed, false);

    const callback = await fetch(minted.url);
    assert.equal(callback.status, 200);
    const seen = JSON.parse(await pluginTools.get("oob_wait").execute({
      token: minted.token,
      timeoutMs: 2000,
      pollMs: 50,
    }));
    assert.equal(seen.confirmed, true);
    assert.ok(seen.kinds.includes("http"));

    const lead = JSON.parse(await router.execute({
      bugClass: "ssrf",
      spec: JSON.stringify({ token: minted.token, session: minted.session }),
    }));
    assert.equal(lead.route, "validate_oob");
    assert.equal(lead.validated, false);
    assert.equal(lead.disposition, "lead");
    assert.equal(lead.interaction_recorded, true);
    assert.equal(lead.evidence.interaction_count, 1);
    assert.equal(lead.evidence.kinds.includes("http"), true);

    const smtp = await fetch(new URL(`/smtp/${minted.token}`, mock.url));
    assert.equal(smtp.status, 200);
    const confirmed = JSON.parse(await router.execute({
      bugClass: "ssrf",
      spec: JSON.stringify({ token: minted.token, session: minted.session }),
    }));
    assert.equal(confirmed.validated, true);
    assert.equal(confirmed.disposition, "confirm");
    assert.equal(confirmed.evidence.interaction_count, 2);
    assert.deepEqual(confirmed.evidence.kinds.sort(), ["http", "smtp"]);
  } finally {
    await pluginTools.get("oob_stop").execute({});
    await mock.close();
  }
});

test("listenLoopback records a real loopback callback for the scan matcher", async () => {
  const oob = await listenLoopback();
  try {
    assert.match(oob.url, /^http:\/\/127\.0\.0\.1:\d+\//);
    assert.ok(oob.url.includes(oob.token));
    const res = await fetch(oob.url);
    assert.equal(res.status, 200);
    assert.equal(oob.hits.length, 1);
    assert.equal(oob.interactions[0].recorded, true);
    assert.equal(oob.interactions[0].token, oob.token);
    assert.equal(oob.interactions[0].kind, "http");
  } finally {
    await oob.close();
  }
});

test("recon-15 plants a minted interactsh URL and promotes only a real callback", async () => {
  const mock = await startMockInteractsh();
  const domainHit = "interactsh-hit.example";
  const domainQuiet = "interactsh-quiet.example";
  const bin = await mkdtemp(join(tmpdir(), "bh-interactsh-"));
  const hunts = [domainHit, domainQuiet].map((d) => join(ROOT, "hunts", d));
  const qsreplace = `#!/bin/bash
payload="$1"
python3 -c '
import sys
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
payload = sys.argv[1]
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    parts = urlsplit(line)
    query = [(k, payload) for k, _ in parse_qsl(parts.query, keep_blank_values=True)]
    print(urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)))
' "$payload"
`;
  const httpx = `#!/bin/bash
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-o" ]; then out="$arg"; fi
  prev="$arg"
done
captured="$(mktemp)"
cat > "$captured"
python3 - "$out" "$captured" <<'PY'
import os, sys
from urllib.parse import parse_qsl, urlsplit
from urllib.request import urlopen
out, src = sys.argv[1], sys.argv[2]
lines = [line.strip() for line in open(src, encoding="utf-8").read().splitlines() if line.strip()]
if out:
    open(out, "w", encoding="utf-8").write("".join(f"{line}\\n" for line in lines))
if os.environ.get("BUGHIVE_HTTPX_NO_FETCH") == "1":
    raise SystemExit(0)
for line in lines:
    parts = urlsplit(line)
    for _, value in parse_qsl(parts.query, keep_blank_values=True):
        try:
            target = urlsplit(value)
        except Exception:
            continue
        if target.hostname == "127.0.0.1":
            try:
                urlopen(value, timeout=2).read()
            except Exception:
                pass
PY
rm -f "$captured"
`;
  await writeFile(join(bin, "qsreplace"), qsreplace);
  await writeFile(join(bin, "httpx"), httpx);
  await chmod(join(bin, "qsreplace"), 0o755);
  await chmod(join(bin, "httpx"), 0o755);
  try {
    for (const domain of [domainHit, domainQuiet]) {
      const hd = join(ROOT, "hunts", domain);
      await rm(hd, { recursive: true, force: true });
      await mkdir(join(hd, "recon"), { recursive: true });
      await writeFile(join(hd, "recon", "all_endpoints"), "https://app.interactsh.test/fetch?url=http://ok.example\n");
    }
    const run = (domain, extra) => new Promise((resolve, reject) => {
      execFile("bash", ["scripts/pipeline/recon-15.sh", domain], {
        cwd: ROOT,
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: `${bin}:${process.env.PATH}`,
          BUGHIVE_COLLABORATOR_URL: mock.url,
          ...extra,
        },
      }, (error, stdout, stderr) => {
        if (error) reject(Object.assign(error, { stdout, stderr }));
        else resolve(stdout);
      });
    });
    await run(domainHit, {});
    const hitPhase = join(ROOT, "hunts", domainHit, "recon", "15-mass-oneliners");
    const hitStatus = await readFile(join(hitPhase, "ssrf-status.txt"), "utf8");
    assert.match(hitStatus, /^status=confirmed\n/);
    const sent = await readFile(join(hitPhase, "provenance", "ssrf-sent.txt"), "utf8");
    assert.match(sent, /127\.0\.0\.1/);
    const summary = JSON.parse(await readFile(join(hitPhase, "summary.json"), "utf8"));
    const ssrf = summary.items.filter((item) => item.bugClass === "ssrf");
    assert.equal(ssrf.length, 1);
    assert.equal(ssrf[0].priority, 9);
    assert.equal(summary.items.some((item) => item.url.includes("ok.example")), false);

    await run(domainQuiet, { BUGHIVE_HTTPX_NO_FETCH: "1" });
    const quietPhase = join(ROOT, "hunts", domainQuiet, "recon", "15-mass-oneliners");
    const quietStatus = await readFile(join(quietPhase, "ssrf-status.txt"), "utf8");
    assert.match(quietStatus, /^status=unconfirmed\n/);
    await assert.rejects(readFile(join(quietPhase, "vuln-ssrf"), "utf8"));
    assert.equal(mock.contacted.some((c) => /projectdiscovery|oast\./i.test(`${c.host}${c.url}`)), false);
  } finally {
    await mock.close();
    await rm(bin, { recursive: true, force: true });
    for (const hd of hunts) await rm(hd, { recursive: true, force: true });
  }
});
