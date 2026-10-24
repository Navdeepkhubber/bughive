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
import { pathToFileURL } from "node:url";
import { analyzeSources } from "./index.js";

import { stat, readdir, readFile } from "node:fs/promises";
import { extname } from "node:path";

const SCANNABLE = new Set([".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".html", ".htm", ".json"]);
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const SNIFF_BYTES = 4096;

/**
 * Guess a scannable extension from a body that was saved without one.
 * Redirect stubs are HTML; real bundles are JS. A known non-empty extension
 * is never overridden — callers only sniff extensionless files.
 */
export function sniffExtension(sample) {
  const raw = Buffer.isBuffer(sample) ? sample.toString("utf8") : String(sample || "");
  if (!raw || raw.includes("\0")) return "";
  const head = raw.replace(/^\uFEFF/, "").trimStart().slice(0, 800);
  if (!head) return "";
  if (
    /^<!doctype\s+html/i.test(head) ||
    /^<\/?[a-z][\s\S]{0,40}>/i.test(head) ||
    /<script[\s>]/i.test(head) ||
    /<head[\s>]/i.test(head) ||
    /<html[\s>]/i.test(head)
  ) {
    return ".html";
  }
  if (head.startsWith("{") || head.startsWith("[")) return ".json";
  if (
    /^\s*(import|export|function|const|let|var|class)\b/.test(head) ||
    /=>/.test(head) ||
    /\b(document|window)\s*[.\[]/.test(head)
  ) {
    return ".js";
  }
  return "";
}

async function fileIsScannable(filePath, name) {
  const ext = extname(name).toLowerCase();
  if (SCANNABLE.has(ext)) return true;
  if (ext) return false;
  try {
    const buf = await readFile(filePath);
    if (buf.length > MAX_FILE_BYTES || buf.includes(0)) return false;
    return SCANNABLE.has(sniffExtension(buf.subarray(0, SNIFF_BYTES)));
  } catch {
    return false;
  }
}

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
    else if (await fileIsScannable(p, e.name)) acc.push(p);
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

const invokedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) await main();
