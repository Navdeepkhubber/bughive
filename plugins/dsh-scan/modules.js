/**
 * Optional external tools. AGPL programs (TruffleHog, BBOT) and Nuclei are
 * invoked only as unmodified binaries on PATH. Their source is not vendored.
 * Semgrep registry rules and the CodeQL CLI are intentionally not called.
 */
import { spawnSync } from "node:child_process";

export function which(bin) {
  const res = spawnSync("bash", ["-lc", `command -v ${bin}`], { encoding: "utf8" });
  const path = (res.stdout || "").trim();
  return res.status === 0 && path ? path : null;
}

export function moduleStatus() {
  return {
    nuclei: which("nuclei") ? "present" : "not-installed",
    trufflehog: which("trufflehog") ? "present" : "not-installed",
    "osv-scanner": which("osv-scanner") ? "present" : "not-installed",
    bbot: which("bbot") ? "present" : "not-installed",
    note: "AGPL tools are subprocesses only. Missing binaries are reported, not treated as a clean scan of that module.",
  };
}
