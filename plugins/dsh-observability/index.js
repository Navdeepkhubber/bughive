import { appendFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { homedir } from "node:os";

export const name = "observability";
export const inject = [];

function sanitizeDomain(d) {
  if (!d || typeof d !== "string") return null;
  const clean = d.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "").toLowerCase();
  return /^[a-z0-9.-]+$/.test(clean) ? clean : null;
}

export function apply(ctx, config = {}) {
  const cfg = {
    globalLog: join(homedir(), ".dsh", "events.jsonl"),
    huntsRoot: join(homedir(), ".dsh", "hunts"),
    ...config,
  };

  const kinds = ["model/response", "tool/call", "finding/validation", "budget/session-usage", "approval/decided"];

  async function append(path, payload) {
    try {
      await mkdir(dirname(path), { recursive: true });
      await appendFile(path, JSON.stringify({ ts: new Date().toISOString(), ...payload }) + "\n");
    } catch (e) {
      console.error("[observability]", e.message);
    }
  }

  async function write(kind, payload) {
    const entry = { kind, ...payload };
    await append(cfg.globalLog, entry);

    // If the event carries a domain, also write per-hunt
    const domain = sanitizeDomain(payload.domain);
    if (domain) {
      await append(join(cfg.huntsRoot, domain, "events.jsonl"), entry);
    }
  }

  for (const k of kinds) ctx.on(k, (payload) => write(k, payload));

  console.log("[observability] writing to", cfg.globalLog, "+ per-hunt when domain present");
}
