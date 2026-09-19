import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";

export const name = "finding-validator";
export const inject = ["tools"];

function sanitizeDomain(d) {
  if (!d || typeof d !== "string") throw new Error("domain is required");
  const clean = d.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "").toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(clean)) throw new Error(`invalid domain: ${d}`);
  return clean;
}

async function doRequest(req) {
  const method = (req.method || "GET").toUpperCase();
  const headers = { "User-Agent": "bughive-validator/1.0", ...(req.headers || {}) };
  const opts = { method, headers, redirect: "manual" };
  if (req.body && method !== "GET" && method !== "HEAD") opts.body = req.body;
  const res = await fetch(req.url, opts);
  const body = await res.text();
  return { status: res.status, headers: Object.fromEntries(res.headers), body };
}

export function apply(ctx, config = {}) {
  const cfg = { huntsRoot: join(homedir(), ".dsh", "hunts"), ...config };

  ctx.tools.register({
    name: "validate_finding",
    description: "Deterministically validate a finding by replaying baseline vs probe and diffing. Writes result to ~/.dsh/hunts/<domain>/findings/.",
    parameters: {
      type: "object",
      properties: {
        domain:   { type: "string", description: "Target domain." },
        baseline: { type: "string", description: "Baseline request as JSON." },
        probe:    { type: "string", description: "Probe request as JSON." },
        label:    { type: "string", description: "Optional short label for the finding." },
      },
      required: ["domain", "baseline", "probe"],
    },
    output: {
      schema: { type: "string" },
      render: (_args, value) => [{ type: "text", text: value }],
    },
    async execute(args) {
      const domain = sanitizeDomain(args.domain);
      const baseline = JSON.parse(args.baseline);
      const probe = JSON.parse(args.probe);

      const b = await doRequest(baseline);
      const p = await doRequest(probe);

      const diff = {
        statusChanged:   b.status !== p.status,
        bodyDiffers:     b.body !== p.body,
        lengthDelta:     Math.abs(b.body.length - p.body.length),
        reflectedMarker: baseline.marker && p.body.includes(baseline.marker),
      };
      const validated = diff.statusChanged || diff.bodyDiffers || diff.reflectedMarker;

      const finding = {
        domain,
        label: args.label || "untitled",
        validated,
        diff,
        baseline: { ...baseline, url: baseline.url, status: b.status },
        probe:    { ...probe,    url: probe.url,    status: p.status },
        ts: new Date().toISOString(),
      };

      const dir = join(cfg.huntsRoot, domain, "findings");
      await mkdir(dir, { recursive: true });
      const path = join(dir, `finding-${Date.now()}.json`);
      await writeFile(path, JSON.stringify(finding, null, 2), "utf-8");

      ctx.emit("finding/validation", { domain, validated, path });

      return JSON.stringify({ validated, diff, path });
    },
  });

  console.log("[finding-validator] registered; writes to", cfg.huntsRoot, "<domain>/findings/");
}
