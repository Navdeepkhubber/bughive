#!/usr/bin/env node
/**
 * plugin-call.mjs — call any bughive plugin tool from bash.
 *
 * WHY THIS EXISTS
 * The plugin tools were only reachable by the DSH agent, so the bash pipeline (recon
 * phases, run.sh) could not use them at all. In practice that meant dedup_assets,
 * retrieve_skills, parse_program_scope, eval_score, coverage_gate and audit_report were
 * written, tested, and never invoked by any real hunt. A capability nothing calls is not
 * a capability.
 *
 * This loads a plugin, wires a minimal context exposing only the `tools` service (which is
 * all the deterministic tools need), and invokes one tool with JSON arguments. The tool's
 * own JSON output is passed through unchanged on stdout, and a non-zero exit signals
 * failure so `set -e` works in bash.
 *
 *   node scripts/plugin-call.mjs dsh-coverage coverage_gate '{"domain":"example.com"}'
 */
import { pathToFileURL } from "node:url";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");

const [, , pluginDir, toolName, argsJson] = process.argv;

function fail(msg, code = 2) {
  process.stderr.write(`plugin-call: ${msg}\n`);
  process.exit(code);
}

if (!pluginDir || !toolName) {
  fail("usage: plugin-call.mjs <plugin-dir> <tool-name> ['<json-args>']");
}

let args = {};
if (argsJson && argsJson.trim()) {
  try {
    args = JSON.parse(argsJson);
  } catch (e) {
    fail(`arguments are not valid JSON: ${e.message}`);
  }
}

// Minimal cordis stand-in: the deterministic tools only need ctx.tools.register.
const registry = new Map();
const ctx = {
  tools: {
    register(def) {
      registry.set(def.name, def);
      return () => registry.delete(def.name);
    },
  },
  on() {},
  emit() {},
  get() {
    return undefined;
  },
  logger: { info() {}, warn() {}, error() {} },
};

const entry = join(ROOT, "plugins", pluginDir, "index.js");
let mod;
try {
  mod = await import(pathToFileURL(entry).href);
} catch (e) {
  fail(`cannot import ${entry}: ${e.message}`);
}

if (typeof mod.apply !== "function") {
  fail(`${pluginDir} does not export apply()`);
}

// Plugin console noise goes to stderr so stdout stays pure JSON for the caller.
const origLog = console.log;
console.log = (...a) => process.stderr.write(a.join(" ") + "\n");
try {
  mod.apply(ctx, {});
} catch (e) {
  console.log = origLog;
  fail(`${pluginDir} failed to apply: ${e.message}`);
}
console.log = origLog;

const tool = registry.get(toolName);
if (!tool) {
  const available = [...registry.keys()].join(", ") || "(none)";
  fail(`${pluginDir} has no tool "${toolName}". Available: ${available}`, 3);
}

let out;
try {
  // Some tools take (args, exec); the deterministic ones ignore the second parameter.
  out = await tool.execute(args, { callId: "plugin-call", name: toolName, signal: undefined });
} catch (e) {
  fail(`${toolName} threw: ${e.message}`, 4);
}

process.stdout.write(String(out ?? "") + "\n");
