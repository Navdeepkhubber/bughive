import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, writeFile, readFile, rm, chmod } from "node:fs/promises";
import { existsSync, readFileSync, appendFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseProgramText } from "../plugins/dsh-scope-intake/index.js";
import { applyPolicy, buildExecutor, huntSnapshot } from "../scripts/pipeline/jev-decide.mjs";
import { loop } from "../scripts/pipeline/jev-loop.mjs";
import { lowProfilePrefix } from "../scripts/pipeline/rate-profile.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOSTS = ["portal.fenz.invalid", "www.fenz.invalid"];
const DOMAIN = "fenz.invalid";
const HOSTS_MARKER = "# bughive-fenz-fixture";

function bash(command, env = {}) {
  return execFileSync("bash", ["-c", command], {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, BUGHIVE_PLANNER: "heuristic", ...env },
  });
}

function policySnap(overrides = {}) {
  return {
    hd: "/tmp/jev-unused",
    done: ["scope", "recon-04", "recon-07"],
    recon: {
      "04-http-probe": { count: 1, items: [{ url: "https://portal.fenz.invalid/" }] },
      "07-js-analysis": { count: 1, files_scanned: 1 },
    },
    present: ["04-http-probe", "07-js-analysis"],
    legal: ["14-nuclei-scan"],
    missing: [],
    keyword: [{ skill: "seeds/idor", score: 4, matched_terms: "userid" }],
    hasKeyword: true,
    hasSelected: true,
    counts: { hypotheses: 0, hypotheses_pass: 0, hypotheses_real: 0, validated: 0, reports: 0, approved: 0 },
    recon_elapsed_seconds: 0,
    recon_max_seconds: 1200,
    policy_flags: [],
    ...overrides,
  };
}

function routing(action, phase = "14_nuclei_scan") {
  return {
    model: "jev-test",
    usage: null,
    answers: {
      next_action: { choice: action, confidence: 0.9, probabilities: {} },
      recon_phase: { choice: phase, confidence: 0.8, probabilities: {} },
      signal: { score: 1, confidence: 0.5 },
      worth_testing: { noul: 0.8 },
      human_review: { noul: 0.91 },
      skill: { choice: "seeds__idor", confidence: 0.7, probabilities: { seeds__idor: 0.7 } },
    },
  };
}

const skills = [{ id: "seeds/idor", key: "seeds__idor", blurb: "swap object ids" }];

const PROGRAM = [
  "Fire and Emergency New Zealand fixture. Local names only. Not a live target.",
  "In scope:",
  "portal.fenz.invalid",
  "www.fenz.invalid",
  "",
  "No disruption of production systems.",
  "Denial of service is prohibited.",
].join("\n");

test("scope intake emits no-disruption and dos into the scope_txt payload", () => {
  const parsed = parseProgramText(PROGRAM);
  const ids = parsed.policy_flags.map((flag) => flag.id);
  assert.ok(ids.includes("no-disruption"), ids.join(","));
  assert.ok(ids.includes("dos"), ids.join(","));
  assert.equal(ids.includes("automated-scanning"), false);
});

test("a dos or no-disruption flag keeps the action and sets rate_profile low", () => {
  const decision = applyPolicy({
    snap: policySnap({ policy_flags: ["no-disruption", "dos"] }),
    skills,
    routing: routing("select_and_test"),
    confirm: null,
  });
  assert.notEqual(decision.next_action, "human_gate");
  assert.equal(decision.rate_profile, "low");
  assert.deepEqual(decision.policy_flags, ["no-disruption", "dos"]);
  const prefixed = buildExecutor({
    ...decision,
    next_action: "deepen_recon",
    recon_phase: "04-http-probe",
    batch_active: true,
  }, DOMAIN);
  assert.match(prefixed.command, /BUGHIVE_HTTPX_RATE=5/);
  assert.match(prefixed.command, /BUGHIVE_HTTPX_THREADS=2/);
  assert.match(prefixed.command, /BUGHIVE_NUCLEI_RATE=5/);
  assert.match(prefixed.command, /BUGHIVE_NUCLEI_CONCURRENCY=2/);
  assert.match(prefixed.command, /BUGHIVE_NUCLEI_BULK=2/);
  assert.match(prefixed.command, /BUGHIVE_NMAP_TOP=100/);
  assert.match(prefixed.command, /batch step fenz\.invalid/);
  assert.equal(prefixed.command.includes("naabu"), false);

  const overridden = lowProfilePrefix({ BUGHIVE_LOW_HTTPX_RATE: "3", BUGHIVE_LOW_NMAP_TOP: "80" });
  assert.match(overridden, /BUGHIVE_HTTPX_RATE=3/);
  assert.match(overridden, /BUGHIVE_HTTPX_THREADS=2/);
  assert.match(overridden, /BUGHIVE_NMAP_TOP=80/);
  assert.match(overridden, /PORT_SCAN_TOP_PORTS=80/);
});

test("automated scanning skips volume phases for that domain and still counts recon-03 done", async () => {
  const decision = applyPolicy({
    snap: policySnap({
      policy_flags: ["automated-scanning", "dos"],
      legal: ["03-port-scan"],
      present: ["02-dns-resolution"],
      recon: { "02-dns-resolution": { count: 1 } },
      hasKeyword: false,
      keyword: [],
    }),
    skills,
    routing: routing("deepen_recon", "03_port_scan"),
    confirm: null,
  }, { routingOnly: true });
  assert.equal(decision.rate_profile, "low");
  assert.equal(decision.next_action, "deepen_recon");
  assert.equal(decision.recon_phase, "03-port-scan");
  assert.equal(decision.skip_recon_phase, true);
  const exec = buildExecutor(decision, "skip-scan.invalid");
  assert.match(exec.command, /mark-skipped skip-scan\.invalid recon-03/);
  assert.match(exec.command, /BUGHIVE_HTTPX_RATE=5/);

  const domain = "skip-scan.invalid";
  const hunt = join(ROOT, "hunts", domain);
  await rm(hunt, { recursive: true, force: true });
  try {
    bash(`bash scripts/pipeline/run.sh mark-skipped ${domain} recon-03`);
    const summary = JSON.parse(await readFile(join(hunt, "recon", "03-port-scan", "summary.json"), "utf8"));
    assert.equal(summary.skipped, true);
    assert.equal(existsSync(join(hunt, ".state", "recon-03.done")), true);
    const snap = await huntSnapshot(domain);
    assert.ok(snap.present.includes("03-port-scan"));
    assert.ok(snap.legal.includes("04-http-probe"), snap.legal.join(","));
  } finally {
    await rm(hunt, { recursive: true, force: true });
  }
});

test("low profile exports honor BUGHIVE_LOW_* and recon-15 passes -rl/-t", async () => {
  const exportsText = bash("python3 scripts/pipeline/_batch.py exports", {
    BUGHIVE_RATE_PROFILE: "low",
    BUGHIVE_LOW_HTTPX_RATE: "4",
    BUGHIVE_LOW_NUCLEI_CONC: "1",
  });
  assert.match(exportsText, /BUGHIVE_HTTPX_RATE='?4'?/);
  assert.match(exportsText, /BUGHIVE_HTTPX_THREADS='?2'?/);
  assert.match(exportsText, /BUGHIVE_NUCLEI_RATE='?5'?/);
  assert.match(exportsText, /BUGHIVE_NUCLEI_CONCURRENCY='?1'?/);
  assert.match(exportsText, /BUGHIVE_NUCLEI_BULK='?2'?/);
  assert.match(exportsText, /BUGHIVE_NMAP_TOP='?100'?/);
  assert.match(exportsText, /NUCLEI_RATE_LIMIT='?5'?/);
  assert.match(exportsText, /PORT_SCAN_TOP_PORTS='?100'?/);

  const domain = "recon15-low.invalid";
  const hunt = join(ROOT, "hunts", domain);
  const bin = await mkdtemp(join(tmpdir(), "bh-httpx-"));
  const log = join(bin, "httpx.log");
  const httpx = `#!/bin/bash
echo "$*" >> "$BUGHIVE_TOOL_LOG"
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-o" ]; then out="$arg"; fi
  prev="$arg"
done
if [ -n "$out" ]; then cat > "$out"; fi
exit 0
`;
  await writeFile(join(bin, "httpx"), httpx);
  await writeFile(join(bin, "qsreplace"), "#!/bin/bash\ncat\n");
  await chmod(join(bin, "httpx"), 0o755);
  await chmod(join(bin, "qsreplace"), 0o755);
  await rm(hunt, { recursive: true, force: true });
  await mkdir(join(hunt, "recon"), { recursive: true });
  await writeFile(join(hunt, "recon", "all_endpoints"), "https://portal.fenz.invalid/search?q=1\n");
  try {
    bash(`bash scripts/pipeline/recon-15.sh ${domain}`, {
      PATH: `${bin}:${process.env.PATH}`,
      BUGHIVE_TOOL_LOG: log,
      BUGHIVE_RATE_PROFILE: "low",
      BUGHIVE_LOW_HTTPX_RATE: "4",
      BUGHIVE_COLLABORATOR_URL: "http://127.0.0.1:9/oob-canary",
    });
    const recorded = await readFile(log, "utf8");
    assert.match(recorded, /-rl 4/);
    assert.match(recorded, /-t 2/);
    assert.equal(recorded.includes("naabu"), false);
  } finally {
    await rm(hunt, { recursive: true, force: true });
    await rm(bin, { recursive: true, force: true });
  }
});

function installStub(bin, name, body) {
  writeFileSync(join(bin, name), body);
  execFileSync("chmod", ["755", join(bin, name)]);
}

test("FENZ fixture pauses after one host at the low profile and does not touch the second", async () => {
  const parsed = parseProgramText(PROGRAM);
  const ids = parsed.policy_flags.map((flag) => flag.id);
  assert.ok(ids.includes("no-disruption"));
  assert.ok(ids.includes("dos"));

  const hunt = join(ROOT, "hunts", DOMAIN);
  const bin = await mkdtemp(join(tmpdir(), "bh-fenz-"));
  const log = join(bin, "tools.log");
  const httpxHosts = join(bin, "httpx-hosts.txt");
  const nucleiLog = join(bin, "nuclei.log");
  const naabuFlag = join(bin, "naabu-called");
  await rm(hunt, { recursive: true, force: true });

  const record = `echo "$0 $*" >> "$BUGHIVE_TOOL_LOG"\n`;
  installStub(bin, "subfinder", `#!/bin/bash\n${record}exit 0\n`);
  installStub(bin, "amass", `#!/bin/bash\n${record}exit 0\n`);
  installStub(bin, "gau", `#!/bin/bash\n${record}exit 0\n`);
  installStub(bin, "waybackurls", `#!/bin/bash\n${record}exit 0\n`);
  installStub(bin, "dig", `#!/bin/bash\n${record}if [ "$2" = "A" ]; then echo 203.0.113.10; fi\nexit 0\n`);
  installStub(bin, "curl", `#!/bin/bash\n${record}exit 0\n`);
  installStub(bin, "nmap", `#!/bin/bash\n${record}exit 0\n`);
  installStub(bin, "katana", `#!/bin/bash\n${record}exit 0\n`);
  installStub(bin, "ffuf", `#!/bin/bash\n${record}exit 0\n`);
  installStub(bin, "naabu", `#!/bin/bash\n${record}echo called >> "$BUGHIVE_NAABU_FLAG"\nexit 0\n`);
  installStub(bin, "httpx", `#!/bin/bash
echo "httpx $*" >> "$BUGHIVE_TOOL_LOG"
list=""
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-l" ]; then list="$arg"; fi
  if [ "$prev" = "-o" ]; then out="$arg"; fi
  prev="$arg"
done
if [ -n "$list" ]; then
  echo "----" >> "$BUGHIVE_HTTPX_HOSTS"
  cat "$list" >> "$BUGHIVE_HTTPX_HOSTS"
fi
if [ -n "$out" ]; then
  if [ -n "$list" ]; then
    python3 - "$list" "$out" <<'PY'
import json, sys
from pathlib import Path
hosts = [h.strip() for h in Path(sys.argv[1]).read_text().splitlines() if h.strip()]
Path(sys.argv[2]).write_text("".join(
    json.dumps({"url": f"https://{h}", "host": h, "input": h, "status_code": 200, "title": "fixture"}) + "\\n"
    for h in hosts
))
PY
  else
    cat > "$out"
  fi
fi
exit 0
`);
  installStub(bin, "nuclei", `#!/bin/bash
echo "nuclei $*" >> "$BUGHIVE_NUCLEI_LOG"
echo "nuclei $*" >> "$BUGHIVE_TOOL_LOG"
list=""
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-l" ]; then list="$arg"; fi
  if [ "$prev" = "-o" ]; then out="$arg"; fi
  prev="$arg"
done
if [ -n "$list" ] && [ -f "$list" ]; then
  echo "----" >> "$BUGHIVE_NUCLEI_LOG"
  cat "$list" >> "$BUGHIVE_NUCLEI_LOG"
fi
if [ -n "$out" ]; then : > "$out"; fi
exit 0
`);

  const hostsFile = "/etc/hosts";
  let hostsOriginal = null;
  try {
    hostsOriginal = readFileSync(hostsFile, "utf8");
    if (!hostsOriginal.includes(HOSTS_MARKER)) {
      appendFileSync(hostsFile, `\n127.0.0.1 ${HOSTS.join(" ")} ${HOSTS_MARKER}\n`);
    }
  } catch {
    hostsOriginal = null;
  }

  const env = {
    PATH: `${bin}:${process.env.PATH}`,
    BUGHIVE_TOOL_LOG: log,
    BUGHIVE_HTTPX_HOSTS: httpxHosts,
    BUGHIVE_NUCLEI_LOG: nucleiLog,
    BUGHIVE_NAABU_FLAG: naabuFlag,
    BUGHIVE_PORTSCAN_ENGINE: "nmap",
    BUGHIVE_KATANA_BUDGET_SECONDS: "1",
    BUGHIVE_TRANCHE_SCAN_BUDGET_SECONDS: "1",
    BUGHIVE_GAU_BUDGET_SECONDS: "30",
    BUGHIVE_DNS_BUDGET_SECONDS: "30",
    BUGHIVE_PLANNER: "heuristic",
  };

  try {
    bash(`bash scripts/pipeline/run.sh init ${DOMAIN} "$(printf '%s\\n' ${HOSTS.join(" ")})"`);
    const scopeLines = (await readFile(join(hunt, "scope.txt"), "utf8")).trim().split("\n");
    assert.deepEqual(scopeLines.sort(), HOSTS.slice().sort());
    await writeFile(join(hunt, "program-scope.json"), `${JSON.stringify(parsed, null, 2)}\n`);

    bash(`bash scripts/pipeline/run.sh decide ${DOMAIN}`, env);
    const saved = JSON.parse(await readFile(join(hunt, "jev-decision.json"), "utf8"));
    assert.notEqual(saved.next_action, "human_gate");
    assert.equal(saved.rate_profile, "low");
    assert.ok(saved.policy_flags.includes("no-disruption"));
    assert.ok(saved.policy_flags.includes("dos"));

    const runOut = bash(`bash scripts/pipeline/run.sh batch run ${DOMAIN}`, env);
    const paused = JSON.parse(runOut.trim());
    assert.equal(paused.paused, true);
    assert.equal(paused.phase, "await_confirm");
    const state = JSON.parse(await readFile(join(hunt, "batch", "state.json"), "utf8"));
    assert.equal(state.phase, "await_confirm");
    assert.equal(state.findings_emitted, true);
    const trancheDir = join(hunt, "batch", "tranche-01");
    const findings = JSON.parse(await readFile(join(trancheDir, "findings.json"), "utf8"));
    assert.equal(findings.emitted, true);

    const touched = (await readFile(httpxHosts, "utf8")).trim().split("\n").filter((line) => line && line !== "----");
    assert.deepEqual(touched, [paused.host]);
    assert.equal(touched.includes(paused.next_host), false);
    assert.equal(HOSTS.includes(paused.host), true);
    assert.equal(HOSTS.includes(paused.next_host), true);
    assert.notEqual(paused.host, paused.next_host);

    const nucleiText = await readFile(nucleiLog, "utf8");
    assert.match(nucleiText, /-rl 5/);
    assert.match(nucleiText, /-c 2/);
    assert.match(nucleiText, /-bs 2/);
    assert.equal(nucleiText.includes(paused.next_host), false);
    const toolLog = await readFile(log, "utf8");
    assert.match(toolLog, /httpx .* -rl 5/);
    assert.match(toolLog, /httpx .* -t 2/);
    assert.equal(existsSync(naabuFlag), false);
    assert.equal(toolLog.includes("\nnaabu ") || toolLog.startsWith("naabu "), false);

    const before = await readFile(httpxHosts, "utf8");
    const prevPlanner = process.env.BUGHIVE_PLANNER;
    process.env.BUGHIVE_PLANNER = "heuristic";
    let gated;
    try {
      gated = await loop(DOMAIN, { maxSteps: 2, approveGates: true });
    } finally {
      if (prevPlanner == null) delete process.env.BUGHIVE_PLANNER;
      else process.env.BUGHIVE_PLANNER = prevPlanner;
    }
    assert.equal(gated.status, "await_confirm");
    assert.equal(gated.decision.executor.resume_command, null);
    assert.equal(gated.decision.executor.await_confirm, true);
    assert.equal(await readFile(httpxHosts, "utf8"), before);

    const cont = bash(`bash scripts/pipeline/run.sh batch continue ${DOMAIN}`, env);
    const second = JSON.parse(cont.trim());
    assert.equal(second.paused, true);
    const after = (await readFile(httpxHosts, "utf8")).trim().split("\n").filter((line) => line && line !== "----");
    assert.ok(after.includes(paused.next_host), after.join(","));
    assert.ok(after.includes(paused.host));
  } finally {
    await rm(hunt, { recursive: true, force: true });
    await rm(bin, { recursive: true, force: true });
    if (hostsOriginal != null) {
      try {
        writeFileSync(hostsFile, hostsOriginal.endsWith("\n") ? hostsOriginal : `${hostsOriginal}\n`);
      } catch {
        /* restoring hosts is best-effort */
      }
    }
  }
});
