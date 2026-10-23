#!/usr/bin/env node
/**
 * bughive scan — in-scope confirmed findings.
 *
 *   node plugins/dsh-scan/cli.mjs --base http://127.0.0.1:8099 --scope-text 127.0.0.1 --out hunts/fixture
 *
 * Exit 2: pipeline broken (no rules, no live target, out of scope, invalid pack).
 * Exit 1: the scan ran but one or more checks errored.
 * Exit 0: scan finished. Zero confirmed findings is a real result only when
 *         the stats line shows rules, requests, and a live target.
 */
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PACK } from "./pack.js";
import { runScan, validatePack, writeScanOutput } from "./index.js";

if (process.argv.includes("--validate")) {
  const skillsDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "skills");
  const result = validatePack(PACK, skillsDir);
  process.stdout.write(`${JSON.stringify({ ok: result.ok, name: result.name, version: result.version, rulesLoaded: result.rulesLoaded, errors: result.errors })}\n`);
  process.exit(result.ok ? 0 : 2);
}

function arg(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? undefined : process.argv[index + 1];
}

function multi(name) {
  const values = [];
  for (let i = 0; i < process.argv.length; i += 1) {
    if (process.argv[i] === name && process.argv[i + 1]) values.push(process.argv[i + 1]);
  }
  return values;
}

const scopeFile = arg("--scope-file");
const scopeText = scopeFile ? await readFile(scopeFile, "utf8") : (arg("--scope-text") || "");
const paths = multi("--path");
const tlsHosts = multi("--tls-host");
const packageJson = arg("--package-json");
const base = arg("--base");
const out = arg("--out");

if (!base && paths.length === 0 && !packageJson && tlsHosts.length === 0) {
  process.stderr.write("usage: cli.mjs --base URL --scope-text HOSTS [--out DIR] [--path FILE] [--package-json FILE] [--tls-host HOST]\n       cli.mjs --validate\n");
  process.exit(2);
}

const result = await runScan({
  base,
  scopeText,
  paths,
  packageJson,
  tlsHosts,
  allowActive: arg("--active") === "1" ? true : undefined,
});

if (out) await writeScanOutput(out, result);
process.stdout.write(result.jsonl);
process.stderr.write(`${result.stats.verdict}\n`);
if (!result.ok) process.exit(2);
if (result.stats.errors > 0) process.exit(1);
