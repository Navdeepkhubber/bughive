/**
 * dsh-hunt-journal — persistent evidence + dead-end memory for a hunt.
 *
 * WHY THIS EXISTS
 * dsh-hunt-state records which *stages* finished (`.done` markers). It does not record
 * what was actually tried, what was observed, or what should never be retried. An agent's
 * context window is volatile and a hunt spans many sessions; without an evidence log the
 * same dead ends get re-walked and real observations get lost between turns.
 *
 * This is the durable memory: append-only JSONL, plus derived queries (tail, open leads,
 * stats). "Dead ends" are first-class because knowing what NOT to retry is worth as much
 * as a lead.
 *
 * NOTE ON huntsRoot
 * The shell pipeline writes to `<repo>/hunts/<domain>` ($WS_ROOT/hunts). The existing
 * dsh-hunt-state plugin defaults to `~/.dsh/hunts`, so the plugin and the CLI disagree
 * about where a hunt lives. This plugin defaults to the repo's `hunts/` so both agree.
 */

import { mkdir, appendFile, readFile, readdir, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const name = "hunt-journal";
export const inject = ["tools"];

const HERE = dirname(fileURLToPath(import.meta.url));
// plugins/dsh-hunt-journal/ -> repo root -> hunts/
const REPO_HUNTS = resolve(HERE, "..", "..", "hunts");

const KINDS = ["request", "observation", "lead", "deadend", "finding", "note"];

function sanitize(domain) {
  if (!domain || typeof domain !== "string") throw new Error("domain is required");
  const clean = domain
    .replace(/^https?:\/\//, "")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "")
    .toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(clean)) throw new Error(`invalid domain: ${domain}`);
  return clean;
}

export function apply(ctx, config = {}) {
  const cfg = { huntsRoot: REPO_HUNTS, ...config };
  const journalPath = (domain) =>
    join(cfg.huntsRoot, sanitize(domain), "journal.jsonl");

  async function readEvents(domain) {
    let raw;
    try {
      raw = await readFile(journalPath(domain), "utf8");
    } catch (err) {
      if (err.code === "ENOENT") return [];
      throw err;
    }
    const out = [];
    for (const line of raw.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try {
        out.push(JSON.parse(t));
      } catch {
        /* skip malformed lines rather than failing the whole read */
      }
    }
    return out;
  }

  ctx.tools.register({
    name: "hunt_journal_append",
    description:
      "Append one durable event to a hunt's journal. Use kind='deadend' for anything that must not be retried, and kind='lead' for a promising but unproven thread. This is the hunt's long-term memory across sessions.",
    parameters: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Hunt domain, e.g. threema.ch." },
        kind: { type: "string", enum: KINDS, description: "Event kind." },
        summary: { type: "string", description: "One-line human-readable summary." },
        detail: { type: "string", description: "Optional JSON object with supporting detail." },
      },
      required: ["domain", "kind", "summary"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const domain = sanitize(args.domain);
      const kind = String(args.kind || "").toLowerCase();
      if (!KINDS.includes(kind)) {
        return JSON.stringify({ appended: false, error: `unknown kind: ${args.kind}` });
      }
      let detail = {};
      if (args.detail) {
        try {
          detail = JSON.parse(args.detail);
        } catch (e) {
          return JSON.stringify({ appended: false, error: `detail is not JSON: ${e.message}` });
        }
      }
      const dir = join(cfg.huntsRoot, domain);
      await mkdir(dir, { recursive: true });
      const event = { kind, summary: String(args.summary), detail, ts: Date.now() / 1000 };
      await appendFile(journalPath(domain), JSON.stringify(event) + "\n");
      return JSON.stringify({ appended: true, domain, kind, path: journalPath(domain) });
    },
  });

  ctx.tools.register({
    name: "hunt_journal_tail",
    description: "Read the most recent journal events for a hunt, optionally filtered by kind.",
    parameters: {
      type: "object",
      properties: {
        domain: { type: "string" },
        kind: { type: "string", enum: KINDS, description: "Optional filter." },
        limit: { type: "number", description: "How many events back (default 20)." },
      },
      required: ["domain"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const events = await readEvents(args.domain);
      const filtered = args.kind
        ? events.filter((e) => e.kind === String(args.kind).toLowerCase())
        : events;
      const limit = Number.isFinite(args.limit) ? Math.max(1, args.limit) : 20;
      return JSON.stringify({
        domain: sanitize(args.domain),
        total: events.length,
        showing: Math.min(limit, filtered.length),
        events: filtered.slice(-limit),
      });
    },
  });

  ctx.tools.register({
    name: "hunt_journal_leads",
    description:
      "List open leads: every 'lead' event whose summary was never subsequently recorded as a 'deadend'. This is the resume-work queue.",
    parameters: {
      type: "object",
      properties: { domain: { type: "string" } },
      required: ["domain"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const events = await readEvents(args.domain);
      const dead = new Set(
        events.filter((e) => e.kind === "deadend").map((e) => e.summary)
      );
      const open = events.filter((e) => e.kind === "lead" && !dead.has(e.summary));
      return JSON.stringify({
        domain: sanitize(args.domain),
        open_leads: open.length,
        leads: open,
      });
    },
  });

  ctx.tools.register({
    name: "hunt_journal_stats",
    description: "Event counts by kind for a hunt, plus total and first/last timestamps.",
    parameters: {
      type: "object",
      properties: { domain: { type: "string" } },
      required: ["domain"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const events = await readEvents(args.domain);
      const byKind = {};
      for (const e of events) byKind[e.kind] = (byKind[e.kind] || 0) + 1;
      return JSON.stringify({
        domain: sanitize(args.domain),
        total: events.length,
        by_kind: byKind,
        first: events.length ? events[0].ts : null,
        last: events.length ? events[events.length - 1].ts : null,
        path: journalPath(args.domain),
      });
    },
  });

  ctx.tools.register({
    name: "hunt_journal_ingest",
    description:
      "Harvest request-like evidence from recon summaries and response caches into the journal, so the hunt's request history is complete without anyone remembering to log it. This is the proxy-history function: claim_audit and coverage depend on it to know what was actually requested. Deduplicates by URL, so it is safe to re-run.",
    parameters: {
      type: "object",
      properties: {
        domain: { type: "string" },
        paths: {
          type: "string",
          description: "Files/directories to harvest (defaults to hunts/<domain>/recon), one per line.",
        },
      },
      required: ["domain"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const domain = sanitize(args.domain);
      const targets = String(args.paths || join(cfg.huntsRoot, domain, "recon"))
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);

      const files = [];
      async function walk(p) {
        let st;
        try {
          st = await stat(p);
        } catch {
          return;
        }
        if (st.isDirectory()) {
          for (const e of await readdir(p, { withFileTypes: true })) await walk(join(p, e.name));
        } else if (/\.(json|jsonl)$/i.test(p)) {
          files.push(p);
        }
      }
      for (const t of targets) await walk(t);

      // Existing URLs, so re-running is idempotent.
      const existing = new Set();
      for (const ev of await readEvents(domain)) {
        const u = ev?.detail?.url;
        if (u) existing.add(String(u));
      }

      const seen = new Set();
      const found = [];
      const harvest = (obj, source) => {
        if (!obj || typeof obj !== "object") return;
        const u = obj.url || obj.endpoint || obj.uri;
        if (typeof u === "string" && /^https?:\/\//i.test(u) && !existing.has(u) && !seen.has(u)) {
          seen.add(u);
          found.push({ url: u, method: (obj.method || "GET").toUpperCase(), source });
        }
      };
      const walkJson = (node, source) => {
        if (Array.isArray(node)) {
          for (const n of node) walkJson(n, source);
        } else if (node && typeof node === "object") {
          harvest(node, source);
          for (const v of Object.values(node)) {
            if (v && typeof v === "object") walkJson(v, source);
          }
        }
      };

      for (const f of files) {
        let text;
        try {
          text = await readFile(f, "utf8");
        } catch {
          continue;
        }
        if (f.endsWith(".jsonl")) {
          for (const line of text.split("\n")) {
            const t = line.trim();
            if (!t) continue;
            try {
              walkJson(JSON.parse(t), f);
            } catch {
              /* skip malformed line */
            }
          }
        } else {
          try {
            walkJson(JSON.parse(text), f);
          } catch {
            /* skip malformed file */
          }
        }
      }

      if (found.length) {
        const dir = join(cfg.huntsRoot, domain);
        await mkdir(dir, { recursive: true });
        const lines = found
          .map((r) =>
            JSON.stringify({
              kind: "request",
              summary: `${r.method} ${r.url} (harvested)`,
              detail: { url: r.url, method: r.method, source: r.source, harvested: true },
              ts: Date.now() / 1000,
            })
          )
          .join("\n");
        await appendFile(journalPath(domain), lines + "\n");
      }

      return JSON.stringify({
        domain,
        files_scanned: files.length,
        already_journaled: existing.size,
        newly_ingested: found.length,
        sample: found.slice(0, 10).map((f) => f.url),
        note:
          files.length === 0
            ? "no recon JSON found — nothing to harvest yet"
            : "Request history now covers harvested recon evidence; claim_audit can use it.",
      });
    },
  });

  console.log("[hunt-journal] registered: append, tail, leads, stats, ingest (root =", cfg.huntsRoot, ")");
}
