#!/usr/bin/env node
/**
 * CLI wrapper around dsh-js-analyzer's rule engine so the bash pipeline
 * (recon-07-js-analysis) can use the same logic as the plugin.
 *
 * Usage: node cli.mjs <scan-dir> [more-dirs...] --out <phase-dir>
 * Writes <phase-dir>/summary.json (phase contract) and <phase-dir>/items.jsonl (leads).
 */
import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { analyzeSources } from "./index.js";

import { stat, readdir, readFile } from "node:fs/promises";
import { extname } from "node:path";

const SCANNABLE = new Set([".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".html", ".htm", ".json"]);
const MAX_FILE_BYTES = 8 * 1024 * 1024;

async function collect(dir, acc = []) {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) await collect(p, acc);
    else if (SCANNABLE.has(extname(e.name).toLowerCase())) acc.push(p);
  }
  return acc;
}

async function main() {
  const argv = process.argv.slice(2);
  const outIdx = argv.indexOf("--out");
  const outDir = outIdx === -1 ? null : argv[outIdx + 1];
  const dirs = (outIdx === -1 ? argv : argv.slice(0, outIdx)).filter(Boolean);
  if (dirs.length === 0) {
    console.error("usage: cli.mjs <scan-dir> [...] --out <phase-dir>");
    process.exit(2);
  }

  const files = [];
  for (const d of dirs) {
    let st;
    try {
      st = await stat(d);
    } catch {
      continue;
    }
    if (st.isDirectory()) await collect(d, files);
    else files.push(d);
  }

  const sources = {};
  for (const f of files) {
    try {
      const st = await stat(f);
      if (st.size > MAX_FILE_BYTES) continue;
      sources[f] = await readFile(f, "utf8");
    } catch {
      /* skip unreadable */
    }
  }

  const res = analyzeSources(sources, { minSeverity: "low" });

  if (outDir) {
    await mkdir(outDir, { recursive: true });
    const itemsPath = join(outDir, "items.jsonl");
    await writeFile(itemsPath, res.findings.map((f) => JSON.stringify(f)).join("\n") + (res.findings.length ? "\n" : ""));
    const endpointsPath = join(outDir, "endpoints.txt");
    await writeFile(endpointsPath, res.endpoints.join("\n") + (res.endpoints.length ? "\n" : ""));
    const summary = {
      phase: "07-js-analysis",
      // The phase contract uses `count`; leads are recon items, not vulnerabilities.
      count: res.findings.length,
      files_scanned: res.files_scanned,
      by_severity: res.by_severity,
      by_rule: res.by_rule,
      endpoints_extracted: res.endpoints.length,
      // High-signal leads, capped so the phase summary stays cheap to read.
      items: res.findings.filter((f) => f.severity === "high").slice(0, 50),
      notes: res.files_scanned === 0 ? ["no scannable assets found under the scan dirs"] : [],
      output_files: [itemsPath, endpointsPath],
    };
    await writeFile(join(outDir, "summary.json"), JSON.stringify(summary, null, 2));
  }

  console.log(
    JSON.stringify({
      phase: "07",
      count: res.findings.length,
      files_scanned: res.files_scanned,
      by_severity: res.by_severity,
    })
  );
}

await main();
