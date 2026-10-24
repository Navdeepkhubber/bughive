/**
 * Optional external tools, invoked as unmodified binaries on PATH.
 *
 * AGPL programs (TruffleHog, BBOT) are not vendored and not linked into a
 * service. BBOT itself is not started: this runner only reports whether the
 * binary exists. Nuclei is started only against an in-scope loopback host,
 * or when the caller sets the active-proof gate. No nuclei-templates copy,
 * semgrep-rules checkout, or CodeQL CLI is bundled.
 *
 * A missing binary is `not-installed`. An empty stdout with a non-zero exit
 * is a module error, not a clean zero. A non-zero exit that still printed
 * JSON is parsed.
 */
import { spawnSync } from "node:child_process";
import { scopeAllows } from "../dsh-scope-guard/index.js";

const BINS = new Set(["nuclei", "trufflehog", "osv-scanner", "bbot"]);
const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
const FINDING_CAP = 200;

export function which(bin) {
  if (!BINS.has(bin)) return null;
  const res = spawnSync("bash", ["-lc", `command -v ${bin}`], { encoding: "utf8" });
  const path = (res.stdout || "").trim();
  return res.status === 0 && path ? path : null;
}

export function moduleStatus(whichImpl = which) {
  return {
    nuclei: whichImpl("nuclei") ? "present" : "not-installed",
    trufflehog: whichImpl("trufflehog") ? "present" : "not-installed",
    "osv-scanner": whichImpl("osv-scanner") ? "present" : "not-installed",
    bbot: whichImpl("bbot") ? "present" : "not-installed",
    note: "AGPL tools are unmodified subprocesses. A missing binary is not a clean result for that module. BBOT is reported and not started.",
  };
}

export function nucleiArgs(base) {
  return [
    "-u", base,
    "-jsonl", "-silent", "-disable-update-check", "-no-interactsh",
    "-rl", "10", "-c", "5", "-timeout", "10", "-retries", "1",
    "-etags", "dos,fuzz",
  ];
}

export function trufflehogArgs(path) {
  return ["filesystem", path, "--json", "--no-update"];
}

export function osvScannerArgs(lockfile) {
  return ["scan", "source", "--lockfile", lockfile, "--format", "json"];
}

function severityOf(value) {
  const text = String(value || "info").toLowerCase();
  return SEVERITIES.has(text) ? text : "info";
}

function redactSecret(value) {
  return String(value ?? "")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "AKIA[redacted]")
    .replace(/("apiKey"\s*:\s*")[^"]+"/g, '$1[redacted]"')
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/-]+=*/g, "$1[redacted]");
}

function clip(value, max = 2000) {
  const text = redactSecret(value);
  return text.length > max ? text.slice(0, max) : text;
}

function isExampleSecret(value) {
  const text = String(value || "");
  return text.includes("AKIAIOSFODNN7EXAMPLE") || text.includes("EXAMPLE");
}

function exchange(method, url, responseBody, status = 0) {
  return {
    request: { method, url: clip(url, 500), headers: {}, body: "" },
    response: { status, headers: {}, body: clip(responseBody) },
  };
}

function parseJsonDocuments(stdout) {
  const trimmed = String(stdout || "").trim();
  if (!trimmed) return { parsed: 0, values: [] };
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const data = JSON.parse(trimmed);
      return { parsed: 1, values: Array.isArray(data) ? data : [data] };
    } catch {
      // Fall through. Nuclei and TruffleHog print one JSON object per line.
    }
  }
  const values = [];
  let parsed = 0;
  for (const line of trimmed.split(/\r?\n/)) {
    const text = line.trim();
    if (!text) continue;
    try {
      values.push(JSON.parse(text));
      parsed += 1;
    } catch {
      // A banner line is ignored when at least one JSON object parsed.
    }
  }
  return { parsed, values };
}

function spawnResult(bin, args, spawnImpl) {
  const res = spawnImpl(bin, args, {
    encoding: "utf8",
    timeout: 120000,
    maxBuffer: 8 * 1024 * 1024,
  });
  return {
    status: res?.status,
    stdout: res?.stdout || "",
    stderr: res?.stderr || "",
    error: res?.error ? String(res.error.message || res.error) : null,
  };
}

function readOutput(result) {
  const trimmed = String(result.stdout || "").trim();
  if (result.error && !trimmed) return { ok: false, message: clip(result.error, 300) };
  if (!trimmed) {
    if (result.status === 0) return { ok: true, values: [] };
    const message = clip(String(result.stderr || "").trim() || `exit ${result.status}`, 300);
    return { ok: false, message };
  }
  const parsed = parseJsonDocuments(result.stdout);
  if (parsed.parsed === 0) {
    return { ok: false, message: clip(String(result.stderr || "").trim() || "stdout was not JSON", 300) };
  }
  return { ok: true, values: parsed.values };
}

function emptyRun(status, extra = {}) {
  return { status, findings: 0, error: extra.error || null, detail: extra.detail || null };
}

export function parseNuclei(values) {
  const records = [];
  for (const row of values) {
    const ruleId = row?.["template-id"] || row?.templateID;
    if (!ruleId) continue;
    const asset = String(row["matched-at"] || row.host || "");
    if (!asset) continue;
    const request = String(row.request || "");
    const response = String(row.response || "");
    const verified = request.trim().length > 0 && response.trim().length > 0;
    let path = null;
    try {
      path = new URL(asset).pathname || "/";
    } catch {
      path = null;
    }
    const extractedList = Array.isArray(row["extracted-results"]) ? row["extracted-results"].map((item) => clip(item, 200)) : [];
    records.push({
      module: "nuclei",
      ruleId: String(ruleId),
      skill: "modules/nuclei",
      class: "nuclei",
      severity: severityOf(row.info?.severity),
      method: null,
      path,
      asset,
      status: verified ? "verified" : "unverified",
      proof: verified
        ? `nuclei ${ruleId} matched ${asset} with a saved request and response.`
        : `nuclei ${ruleId} matched ${asset} without a saved request and response, so it stays unverified.`,
      exchanges: verified ? [exchange("NUCLEI", asset, `REQUEST\n${request}\n\nRESPONSE\n${response}`)] : [],
      extracted: extractedList.length ? { results: extractedList.join("\n") } : undefined,
    });
    if (records.length >= FINDING_CAP) break;
  }
  return records;
}

export function parseTrufflehog(values, fallbackPath) {
  const records = [];
  for (const row of values) {
    const detector = String(row.DetectorName || row.detectorName || "");
    if (!detector) continue;
    const raw = String(row.Raw || row.raw || "");
    const redacted = String(row.Redacted || row.redacted || "");
    if (isExampleSecret(raw) || isExampleSecret(redacted)) continue;
    const verified = row.Verified === true || row.verified === true;
    const file = row.SourceMetadata?.Data?.Filesystem?.file
      || row.SourceMetadata?.Data?.Git?.file
      || fallbackPath;
    const line = row.SourceMetadata?.Data?.Filesystem?.line
      || row.SourceMetadata?.Data?.Git?.line
      || 1;
    const asset = `file:${file}`;
    const shown = redacted ? clip(redacted, 80) : "[redacted secret]";
    records.push({
      module: "trufflehog",
      ruleId: `trufflehog-${detector.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
      skill: "modules/trufflehog",
      class: "secret",
      severity: verified ? "high" : "medium",
      method: "FILE",
      path: String(file),
      line,
      asset,
      status: verified ? "verified" : "unverified",
      proof: verified
        ? `trufflehog ${detector} verified a secret at ${file}:${line}. The raw value was not stored.`
        : `trufflehog ${detector} found an unverified secret at ${file}:${line}. Unverified detector output is not confirmed.`,
      exchanges: [exchange("FILE", asset, JSON.stringify({ detector, verified, redacted: shown }), verified ? 200 : 0)],
    });
    if (records.length >= FINDING_CAP) break;
  }
  return records;
}

export function parseOsvScanner(values) {
  const records = [];
  for (const doc of values) {
    const results = doc?.results || doc?.Results || [];
    for (const result of results) {
      for (const pkg of result.packages || result.Packages || []) {
        const info = pkg.package || pkg.Package || {};
        const name = info.name || info.Name || "unknown";
        const version = info.version || info.Version || "";
        const vulns = pkg.vulnerabilities || pkg.Vulnerabilities || [];
        for (const vuln of vulns) {
          const id = vuln.id || vuln.ID;
          if (!id) continue;
          const summary = String(vuln.summary || vuln.Summary || "");
          const aliases = vuln.aliases || vuln.Aliases || [];
          const compact = { id, summary, aliases };
          records.push({
            module: "osv-scanner",
            ruleId: `osv-${id}`,
            skill: "modules/osv-scanner",
            class: "sca",
            severity: "high",
            method: "EXEC",
            path: null,
            asset: `npm:${name}@${version}`,
            status: "verified",
            advisories: [id],
            proof: `${name}@${version} is reported by osv-scanner as ${id}.`,
            exchanges: [exchange("EXEC", "osv-scanner", JSON.stringify(compact), 200)],
          });
          if (records.length >= FINDING_CAP) return records;
        }
      }
    }
  }
  return records;
}

function runOne(bin, args, spawnImpl, parse) {
  try {
    const result = spawnResult(bin, args, spawnImpl);
    const output = readOutput(result);
    if (!output.ok) return { status: "error", findings: 0, error: output.message, records: [], detail: null };
    const records = parse(output.values);
    return { status: "ran", findings: records.length, error: null, records, detail: null };
  } catch (error) {
    return { status: "error", findings: 0, error: clip(error.message, 300), records: [], detail: null };
  }
}

/**
 * Spawn nuclei, trufflehog, and osv-scanner when they are on PATH.
 * Returns plain records. The caller turns them into findings.
 */
export function runExternalModules(opts = {}) {
  const whichImpl = opts.whichImpl || which;
  const spawnImpl = opts.spawnImpl || spawnSync;
  const moduleRuns = {};
  const records = [];
  let requests = 0;
  let errors = 0;

  function take(name, run) {
    moduleRuns[name] = {
      status: run.status,
      findings: run.findings || 0,
      error: run.error || null,
      detail: run.detail || null,
    };
    if (run.status === "error") errors += 1;
    if (run.records?.length) records.push(...run.records);
  }

  const nucleiBin = whichImpl("nuclei");
  if (!nucleiBin) {
    take("nuclei", emptyRun("not-installed"));
  } else if (!opts.base) {
    take("nuclei", emptyRun("skipped", { detail: "no base URL" }));
  } else if (!opts.allowActive) {
    take("nuclei", emptyRun("skipped", { detail: "nuclei stays on loopback unless BUGHIVE_ACTIVE_PROOF=1" }));
  } else {
    let host = "";
    try {
      host = new URL(opts.base).hostname;
    } catch (error) {
      take("nuclei", emptyRun("error", { error: error.message }));
    }
    if (!moduleRuns.nuclei) {
      const gate = scopeAllows(opts.scopeText || "", host);
      if (!gate.allowed) {
        take("nuclei", emptyRun("skipped", { detail: `${host} out of scope` }));
      } else {
        requests += 1;
        take("nuclei", runOne("nuclei", nucleiArgs(opts.base), spawnImpl, parseNuclei));
      }
    }
  }

  const truffleBin = whichImpl("trufflehog");
  const paths = opts.paths || [];
  if (!truffleBin) {
    take("trufflehog", emptyRun("not-installed"));
  } else if (paths.length === 0) {
    take("trufflehog", emptyRun("skipped", { detail: "no files were passed" }));
  } else {
    const merged = [];
    const problems = [];
    for (const path of paths) {
      requests += 1;
      const run = runOne("trufflehog", trufflehogArgs(path), spawnImpl, (values) => parseTrufflehog(values, path));
      merged.push(...(run.records || []));
      if (run.status === "error") problems.push(run.error);
    }
    take("trufflehog", {
      status: problems.length ? "error" : "ran",
      findings: merged.length,
      error: problems[0] || null,
      records: merged,
      detail: null,
    });
  }

  const osvBin = whichImpl("osv-scanner");
  if (!osvBin) {
    take("osv-scanner", emptyRun("not-installed"));
  } else if (!opts.packageJson) {
    take("osv-scanner", emptyRun("skipped", { detail: "no package manifest was passed" }));
  } else {
    requests += 1;
    take("osv-scanner", runOne("osv-scanner", osvScannerArgs(opts.packageJson), spawnImpl, parseOsvScanner));
  }

  const bbotBin = whichImpl("bbot");
  if (!bbotBin) {
    take("bbot", emptyRun("not-installed"));
  } else {
    take("bbot", emptyRun("skipped", { detail: "BBOT is AGPL and is not started; nuclei, trufflehog, and osv-scanner are the subprocess modules" }));
  }

  return { records, moduleRuns, requests, errors };
}
