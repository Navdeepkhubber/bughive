import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, writeFile, readFile, rm, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ROOTS = ["alpha.d2batch.test", "beta.d2batch.test", "gamma.d2batch.test"];

function bash(script, env = {}) {
  return execFileSync("bash", ["-lc", script], {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

test("line_count is one integer when grep -c exits 1", () => {
  const out = bash(`
    set -euo pipefail
    source scripts/pipeline/_common.sh
    f=$(mktemp)
    : > "$f"
    # The old idiom: grep prints 0 and exits 1, so "|| echo 0" appends a second 0.
    broken=$(grep -c . "$f" || echo 0)
    printf 'broken-lines=%s\\n' "$(printf '%s\n' "$broken" | wc -l | tr -d ' ')"
    printf 'broken-value=%s\\n' "$(printf '%s' "$broken" | tr '\n' '|')"
    printf 'empty=%s' "$(line_count "$f")"
    printf '\\n'
    printf 'a\\nb\\n' > "$f"
    printf 'two=%s' "$(line_count "$f")"
    printf '\\n'
    rm -f "$f"
    line_count /no/such/oob-hits
  `);
  const lines = out.trim().split("\n");
  assert.deepEqual(lines, [
    "broken-lines=2",
    "broken-value=0|0",
    "empty=0",
    "two=2",
    "0",
  ]);
  assert.equal(out.includes("0\n0"), false);
});

test("recon-01 enumerates every root in one subfinder -dL and one amass -df under the phase clock", async () => {
  const domain = "d2-batch.example";
  const hd = join(ROOT, "hunts", domain);
  const bin = await mkdtemp(join(tmpdir(), "bh-d2-bin-"));
  const log = join(bin, "enum.log");
  const stub = `#!/bin/bash
log="\${BH_ENUM_LOG:?}"
parent=$(tr '\\0' ' ' < /proc/$PPID/cmdline)
printf '%s\\t%s\\n' "$parent" "$*" >> "$log"
out=""
list=""
prev=""
for arg in "$@"; do
  case "$prev" in
    -o) out="$arg" ;;
    -dL|-df) list="$arg" ;;
  esac
  prev="$arg"
done
if [ -n "$out" ] && [ -n "$list" ] && [ -f "$list" ]; then
  cp "$list" "$out"
fi
exit 0
`;
  await writeFile(join(bin, "subfinder"), stub);
  await writeFile(join(bin, "amass"), stub);
  await chmod(join(bin, "subfinder"), 0o755);
  await chmod(join(bin, "amass"), 0o755);
  await rm(hd, { recursive: true, force: true });
  await mkdir(hd, { recursive: true });
  await writeFile(join(hd, "scope.txt"), ROOTS.join("\n") + "\n");
  try {
    bash(`bash scripts/pipeline/recon-01.sh ${domain}`, {
      PATH: `${bin}:${process.env.PATH}`,
      BH_ENUM_LOG: log,
      BUGHIVE_SUBFINDER_BUDGET_SECONDS: "120",
      BUGHIVE_SUBFINDER_PER_ROOT_SECONDS: "15",
      BUGHIVE_AMASS_PER_ROOT_SECONDS: "15",
    });
    const calls = (await readFile(log, "utf8")).trim().split("\n");
    assert.equal(calls.length, 2, calls.join("\n"));
    const sub = calls.find((line) => line.includes(" subfinder "));
    const amass = calls.find((line) => line.includes(" amass "));
    assert.ok(sub, calls.join("\n"));
    assert.ok(amass, calls.join("\n"));
    assert.match(sub, /(?:^| )-dL(?: |$)/);
    assert.match(amass, /(?:^| )-df(?: |$)/);
    assert.doesNotMatch(sub, /(?:^| )-d /);
    assert.doesNotMatch(amass, /(?:^| )-d /);
    for (const line of calls) {
      const timeoutSeconds = Number(line.match(/(?:^|\s)timeout\s+(\d+)/)?.[1]);
      assert.ok(timeoutSeconds >= 100, line);
      assert.ok(timeoutSeconds <= 120, line);
    }
    const listed = (await readFile(join(hd, "recon/01-subdomain-enum/enum-roots.txt"), "utf8"))
      .trim().split("\n");
    assert.deepEqual(listed, ROOTS);
    const summary = JSON.parse(await readFile(join(hd, "recon/01-subdomain-enum/summary.json"), "utf8"));
    assert.equal(summary.truncated, false);
    assert.equal(summary.degraded, false);
    assert.deepEqual(summary.tools_run, ["subfinder", "amass"]);
    assert.equal(summary.count_total_discovered, ROOTS.length);
    const src = await readFile(join(ROOT, "scripts/pipeline/recon-01.sh"), "utf8");
    assert.match(src, /subfinder -dL/);
    assert.match(src, /amass enum -passive -df/);
    assert.doesNotMatch(src, /for root in/);
  } finally {
    await rm(hd, { recursive: true, force: true });
    await rm(bin, { recursive: true, force: true });
  }
});

function statusHits(text) {
  const line = text.split("\n").find((row) => row.startsWith("hits="));
  assert.ok(line, text);
  const hits = line.slice("hits=".length);
  assert.match(hits, /^[0-9]+$/);
  assert.equal(hits.includes("\n"), false);
  return hits;
}

async function runPhase15(domain, { oob } = {}) {
  const hd = join(ROOT, "hunts", domain);
  const bin = await mkdtemp(join(tmpdir(), "bh-d7-bin-"));
  const httpx = `#!/bin/bash
out=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-o" ]; then out="$arg"; fi
  prev="$arg"
done
if [ -z "$out" ]; then
  echo "httpx stub: missing -o" >&2
  exit 2
fi
cat > "$out"
`;
  await writeFile(join(bin, "qsreplace"), "#!/bin/bash\ncat\n");
  await writeFile(join(bin, "httpx"), httpx);
  await chmod(join(bin, "qsreplace"), 0o755);
  await chmod(join(bin, "httpx"), 0o755);
  await rm(hd, { recursive: true, force: true });
  const phase = join(hd, "recon", "15-mass-oneliners");
  await mkdir(join(hd, "recon"), { recursive: true });
  const sent = [
    "https://app.d7batch.test/search?q=1",
    "https://app.d7batch.test/fetch?url=http://ok.example",
  ];
  await writeFile(join(hd, "recon", "all_endpoints"), sent.join("\n") + "\n");
  if (oob) {
    await mkdir(phase, { recursive: true });
    await writeFile(join(phase, "oob.jsonl"), JSON.stringify({
      kind: "http",
      ts: "2026-01-01T00:00:00Z",
      method: "GET",
      host: "127.0.0.1:8787",
      path: "/deadbeef",
      source_ip: "127.0.0.1",
    }) + "\n");
  }
  bash(`bash scripts/pipeline/recon-15.sh ${domain}`, {
    PATH: `${bin}:${process.env.PATH}`,
    BUGHIVE_COLLABORATOR_URL: "http://127.0.0.1:9/oob-canary",
  });
  const summary = JSON.parse(await readFile(join(phase, "summary.json"), "utf8"));
  const status = await readFile(join(phase, "ssrf-status.txt"), "utf8");
  const sentBody = await readFile(join(phase, "provenance", "ssrf-sent.txt"), "utf8");
  return { hd, bin, summary, status, sentBody, sent, phase };
}

test("recon-15 promotes an SSRF candidate only when oob-hits is non-empty", async () => {
  const src = await readFile(join(ROOT, "scripts/pipeline/recon-15.sh"), "utf8");
  assert.equal(src.includes("|| echo 0"), false);
  assert.match(src, /httpx -fr/);
  assert.match(src, /provenance\/ssrf-sent\.txt/);
  assert.doesNotMatch(src, /httpx -fr[^\n]*vuln-ssrf/);

  let quiet;
  let hit;
  try {
    quiet = await runPhase15("d7-unconfirmed.example");
    const quietSsrf = quiet.summary.items.filter((item) => item.bugClass === "ssrf");
    assert.equal(quietSsrf.length, 0);
    assert.equal(statusHits(quiet.status), "0");
    assert.match(quiet.status, /^status=unconfirmed\n/);
    assert.equal(await readFile(join(quiet.phase, "vuln-ssrf"), "utf8").catch((err) => err.code), "ENOENT");
    const sentLines = quiet.sentBody.trim().split("\n").filter(Boolean);
    assert.deepEqual(sentLines, quiet.sent);

    hit = await runPhase15("d7-confirmed.example", { oob: true });
    const hitSsrf = hit.summary.items.filter((item) => item.bugClass === "ssrf");
    assert.equal(hitSsrf.length, 1);
    assert.equal(hitSsrf[0].priority, 9);
    assert.equal(hitSsrf[0].source, "vuln-ssrf");
    assert.match(hitSsrf[0].url, /deadbeef/);
    assert.equal(statusHits(hit.status), "1");
    assert.match(hit.status, /^status=confirmed\n/);
    for (const url of hit.sent) {
      assert.equal(hitSsrf.some((item) => item.url === url), false);
    }
    const oobHits = (await readFile(join(hit.phase, "oob-hits"), "utf8")).trim().split("\n");
    assert.equal(oobHits.length, 1);
    assert.equal(hitSsrf.length, oobHits.length);
  } finally {
    if (quiet) {
      await rm(quiet.hd, { recursive: true, force: true });
      await rm(quiet.bin, { recursive: true, force: true });
    }
    if (hit) {
      await rm(hit.hd, { recursive: true, force: true });
      await rm(hit.bin, { recursive: true, force: true });
    }
  }
});
