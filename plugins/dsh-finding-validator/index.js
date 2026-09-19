import { execFile } from "node:child_process";
import { promisify } from "node:util";

export const name = "finding-validator";
export const inject = ["tools"];

const execFileP = promisify(execFile);
const STATUS_MARKER = "__DSH_HTTP_STATUS__";

// --- request normalization -------------------------------------------------

function normalizeRequest(raw, label) {
  let obj = raw;
  if (typeof raw === "string") obj = { url: raw };
  const url = obj && (obj.url || obj.target || obj.endpoint);
  if (!url || typeof url !== "string") {
    return { error: { code: "INVALID_REQUEST", message: `${label} is missing a non-empty \`url\` (or \`target\`/\`endpoint\`)` } };
  }
  return {
    request: {
      url,
      method: (obj.method || "GET").toUpperCase(),
      headers: obj.headers || {},
      body: obj.body,
      marker: obj.marker,
      timeoutMs: obj.timeoutMs,
    },
  };
}

function isPlainGet(req) {
  return req.method === "GET" && Object.keys(req.headers || {}).length === 0 && req.body === undefined;
}

// --- transports --------------------------------------------------------

async function webFetch(ctx, req, signal) {
  const web = ctx.get("web");
  try {
    const result = await web.fetch({ url: req.url }, signal);
    if (!result || typeof result.statusCode !== "number" || !result.body || typeof result.body.content !== "string") {
      return { transport: "web", error: { code: "WEB_BAD_RESPONSE", message: "ctx.web.fetch returned a malformed response" } };
    }
    return { transport: "web", status: result.statusCode, body: result.body.content };
  } catch (e) {
    return { transport: "web", error: { code: e.code || "WEB_FETCH_FAILED", message: e.message || String(e) } };
  }
}

async function curlFetch(req, timeoutMs) {
  const method = req.method || "GET";
  const args = ["-sS", "--max-time", String(Math.ceil(timeoutMs / 1000))];
  if (method === "HEAD") args.push("--head"); // NOT -X HEAD: that makes curl wait for a body that never arrives
  else if (method !== "GET") args.push("-X", method);
  for (const [k, v] of Object.entries(req.headers || {})) args.push("-H", `${k}: ${v}`);
  if (req.body !== undefined && req.body !== null && method !== "GET" && method !== "HEAD") {
    args.push("--data-binary", String(req.body));
  }
  args.push("-o", "-", "-w", `\n${STATUS_MARKER}%{http_code}`, req.url);

  try {
    const { stdout } = await execFileP("curl", args, { timeout: timeoutMs + 2000, maxBuffer: 20 * 1024 * 1024 });
    const markerNL = `\n${STATUS_MARKER}`;
    const idx = stdout.lastIndexOf(markerNL);
    if (idx === -1) {
      return { transport: "curl", error: { code: "CURL_BAD_OUTPUT", message: "curl output missing status marker" } };
    }
    const body = stdout.slice(0, idx);
    const status = parseInt(stdout.slice(idx + markerNL.length), 10);
    return { transport: "curl", status, body };
  } catch (e) {
    if (e.killed || e.signal) return { transport: "curl", error: { code: "CURL_TIMEOUT", message: e.message } };
    if (e.code === "ENOENT") return { transport: "curl", error: { code: "CURL_SPAWN_FAILED", message: e.message } };
    const exitCode = typeof e.code === "number" || typeof e.code === "string" ? e.code : "UNKNOWN";
    return { transport: "curl", error: { code: `CURL_EXIT_${exitCode}`, message: e.message } };
  }
}

async function fetchOne(ctx, req, timeoutMs, signal) {
  const web = ctx.get("web");
  if (isPlainGet(req) && web) return webFetch(ctx, req, signal);
  return curlFetch(req, timeoutMs);
}

// --- noise normalization for the validated/not decision --------------------
// Two requests to a live target almost always differ *somewhere* --
// timestamps, CSRF tokens, nonces, request IDs. Comparing raw bytes treats
// that noise as proof. Strip known-dynamic shapes before deciding whether a
// diff means anything.
function stripNoise(body) {
  return (body || "")
    .replace(/\b\d{10,13}\b/g, "<NUM>")
    .replace(/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?\b/g, "<TS>")
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, "<UUID>")
    .replace(/\b[A-Za-z0-9_-]{24,}\b/g, "<TOKEN>")
    .replace(/\s+/g, " ")
    .trim();
}
const MIN_MEANINGFUL_LENGTH_DELTA = 8;

export function apply(ctx, config = {}) {
  const cfg = { timeoutMs: 10000, maxAttempts: 1, requireResponseDiff: true, ...config };

  ctx.tools.register({
    name: "validate_finding",
    description: "Deterministically validate a finding by replaying baseline vs probe and diffing (ctx.web for plain GETs, curl fallback for anything else). Never throws on a network/parse error -- returns a structured error instead.",
    parameters: {
      type: "object",
      properties: {
        baseline: { type: "string", description: "Baseline request as JSON ({url|target|endpoint, method?, headers?, body?})." },
        probe: { type: "string", description: "Probe request as JSON, same shape." },
        label: { type: "string", description: "Optional short label for the finding." },
      },
      required: ["baseline", "probe"],
    },
    output: {
      schema: { type: "string" },
      render: (_args, value) => [{ type: "text", text: value }],
    },
    async execute(args, exec) {
      const signal = exec && exec.signal;
      const timeoutMs = cfg.timeoutMs;

      let baselineRaw, probeRaw;
      try { baselineRaw = JSON.parse(args.baseline); } catch {
        return JSON.stringify({ validated: false, diff: { statusChanged: false, lengthDelta: 0, bodyDiffers: false }, error: { code: "BASELINE_JSON_PARSE", message: "baseline is not valid JSON" } });
      }
      try { probeRaw = JSON.parse(args.probe); } catch {
        return JSON.stringify({ validated: false, diff: { statusChanged: false, lengthDelta: 0, bodyDiffers: false }, error: { code: "PROBE_JSON_PARSE", message: "probe is not valid JSON" } });
      }

      const baselineN = normalizeRequest(baselineRaw, "baseline");
      const probeN = normalizeRequest(probeRaw, "probe");
      const firstShapeError = baselineN.error || probeN.error;
      if (firstShapeError) {
        return JSON.stringify({ validated: false, diff: { statusChanged: false, lengthDelta: 0, bodyDiffers: false }, error: firstShapeError });
      }

      const [b, p] = await Promise.all([
        fetchOne(ctx, baselineN.request, timeoutMs, signal),
        fetchOne(ctx, probeN.request, timeoutMs, signal),
      ]);

      const statuses = { baseline: typeof b.status === "number" ? b.status : null, probe: typeof p.status === "number" ? p.status : null };
      const transports = { baseline: b.transport, probe: p.transport };

      const firstTransportError = b.error || p.error;
      if (firstTransportError) {
        const result = {
          validated: false,
          diff: { statusChanged: false, lengthDelta: 0, bodyDiffers: false },
          error: firstTransportError,
          statuses,
          transports,
        };
        ctx.emit("finding/validation", { label: args.label || "untitled", ...result });
        return JSON.stringify(result);
      }

      // Raw diff -- preserved exactly for compatibility with existing
      // consumers/tests: statusChanged / lengthDelta / bodyDiffers on the
      // literal bytes.
      const statusChanged = b.status !== p.status;
      const bodyDiffers = b.body !== p.body;
      const lengthDelta = Math.abs((b.body || "").length - (p.body || "").length);
      const diff = { statusChanged, lengthDelta, bodyDiffers };
      const validated = statusChanged || bodyDiffers;

      // Additional noise-aware read, surfaced alongside the raw diff rather
      // than replacing it: two identical-looking requests differing only in
      // a timestamp/token still show bodyDiffers=true above (by design, for
      // compatibility) but normalizedBodyDiffers=false tells a caller that
      // the raw diff is very likely noise, not evidence.
      const reflectedMarker = Boolean(baselineN.request.marker) && (p.body || "").includes(baselineN.request.marker);
      const normalizedBodyDiffers = stripNoise(b.body) !== stripNoise(p.body);
      const meaningfulBodyDiff = normalizedBodyDiffers && lengthDelta >= MIN_MEANINGFUL_LENGTH_DELTA;
      const confidence = reflectedMarker || statusChanged ? "high" : meaningfulBodyDiff ? "medium" : (validated ? "low-likely-noise" : "none");

      const result = {
        validated,
        diff,
        confidence,
        normalizedBodyDiffers,
        reflectedMarker,
        statuses,
        transports,
      };
      ctx.emit("finding/validation", { label: args.label || "untitled", ...result });
      return JSON.stringify(result);
    },
  });

  console.log("[finding-validator] registered; timeoutMs =", cfg.timeoutMs);
}
