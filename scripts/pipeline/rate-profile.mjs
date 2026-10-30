/**
 * Low / no-disruption rate profile.
 *
 * Throughput numbers stay in batch-defaults.json. This profile is selected
 * per domain when program policy carries no-disruption, critical-infrastructure,
 * or dos. BUGHIVE_LOW_* overrides the baked-in number so the caps can be
 * tuned without a code change. A set override wins over the default.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PROFILE_PATH = join(dirname(fileURLToPath(import.meta.url)), "data", "rate-profiles.json");

export const LOW_RATE_FLAGS = new Set(["no-disruption", "critical-infrastructure", "dos"]);
export const FORBID_SCAN_FLAGS = new Set(["automated-scanning"]);

/** Volume phases skipped when the program forbids automated scanning. */
export const SKIP_SCAN_PHASES = new Set([
  "03-port-scan",
  "05-content-discovery",
  "14-nuclei-scan",
  "15-mass-oneliners",
]);

export const SKIP_SCAN_STAGES = new Set(["recon-03", "recon-05", "recon-14", "recon-15"]);

let cached;

export function lowProfileSpec() {
  if (!cached) {
    const raw = JSON.parse(readFileSync(PROFILE_PATH, "utf8"));
    cached = raw.low;
  }
  return cached;
}

function intOr(raw, fallback) {
  if (raw == null || String(raw).trim() === "") return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value)) return fallback;
  return Math.trunc(value);
}

/** Resolved low-profile number. BUGHIVE_LOW_* wins when it is set. */
export function lowProfileValue(key, env = process.env) {
  const spec = lowProfileSpec();
  const fallback = intOr(spec[key], 0);
  const overrideName = spec.overrides?.[key];
  if (!overrideName) return fallback;
  return intOr(env[overrideName], fallback);
}

export function lowProfileMap(env = process.env) {
  const spec = lowProfileSpec();
  const out = {};
  for (const key of Object.keys(spec.overrides || {})) {
    out[key] = lowProfileValue(key, env);
  }
  return out;
}

/**
 * Shell assignments for a low-profile command. Values are integers from the
 * profile, so they do not need quoting. Includes the aliases recon phases read
 * (PORT_SCAN_TOP_PORTS, NUCLEI_RATE_LIMIT) as well as the BUGHIVE_* knobs.
 */
export function lowProfilePrefix(env = process.env) {
  const v = lowProfileMap(env);
  return [
    "BUGHIVE_RATE_PROFILE=low",
    `BUGHIVE_HTTPX_RATE=${v.BUGHIVE_HTTPX_RATE}`,
    `BUGHIVE_HTTPX_THREADS=${v.BUGHIVE_HTTPX_THREADS}`,
    `BUGHIVE_NUCLEI_RATE=${v.BUGHIVE_NUCLEI_RATE}`,
    `BUGHIVE_NUCLEI_CONCURRENCY=${v.BUGHIVE_NUCLEI_CONCURRENCY}`,
    `BUGHIVE_NUCLEI_BULK=${v.BUGHIVE_NUCLEI_BULK}`,
    `BUGHIVE_NMAP_TOP=${v.BUGHIVE_NMAP_TOP}`,
    `PORT_SCAN_TOP_PORTS=${v.BUGHIVE_NMAP_TOP}`,
    `NUCLEI_RATE_LIMIT=${v.BUGHIVE_NUCLEI_RATE}`,
  ].join(" ");
}

export function lowProfileEnv(env = process.env) {
  const v = lowProfileMap(env);
  return {
    BUGHIVE_RATE_PROFILE: "low",
    BUGHIVE_HTTPX_RATE: String(v.BUGHIVE_HTTPX_RATE),
    BUGHIVE_HTTPX_THREADS: String(v.BUGHIVE_HTTPX_THREADS),
    BUGHIVE_NUCLEI_RATE: String(v.BUGHIVE_NUCLEI_RATE),
    BUGHIVE_NUCLEI_CONCURRENCY: String(v.BUGHIVE_NUCLEI_CONCURRENCY),
    BUGHIVE_NUCLEI_BULK: String(v.BUGHIVE_NUCLEI_BULK),
    BUGHIVE_NMAP_TOP: String(v.BUGHIVE_NMAP_TOP),
    PORT_SCAN_TOP_PORTS: String(v.BUGHIVE_NMAP_TOP),
    NUCLEI_RATE_LIMIT: String(v.BUGHIVE_NUCLEI_RATE),
  };
}

export function policyFlagIds(raw) {
  const list = Array.isArray(raw) ? raw : [];
  const ids = [];
  for (const item of list) {
    const id = typeof item === "string" ? item : item?.id;
    if (typeof id === "string" && id.trim()) ids.push(id.trim());
  }
  return ids;
}

/** no-disruption / critical-infrastructure / dos → low. automated-scanning → skip volume phases. */
export function classifyPolicy(raw) {
  const ids = policyFlagIds(raw);
  return {
    ids,
    low: ids.some((id) => LOW_RATE_FLAGS.has(id)),
    forbidScans: ids.some((id) => FORBID_SCAN_FLAGS.has(id)),
  };
}

export function isLowProfile(env = process.env) {
  return String(env.BUGHIVE_RATE_PROFILE || "").trim().toLowerCase() === "low";
}
