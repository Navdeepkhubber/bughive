/**
 * dsh-claim-audit — bind every claim in a report to actual evidence.
 *
 * WHY THIS EXISTS
 * The failure mode this closes is not a missed bug, it is a FALSE REPORT. In this very
 * repository's history an engagement report asserted "no SQLi indicators on
 * invoice_ref, check, fetch_bulk, or create" when payloads had been sent to exactly one
 * of those four endpoints. Nothing in the pipeline could notice, because nothing compared
 * what the report claimed against what the hunt actually did.
 *
 * HOW IT CHECKS
 * Two levels, because they catch different lies:
 *   1. Endpoint presence -- was this endpoint requested at all?
 *   2. Technique correlation -- the sentence claims a technique (SQLi, XSS, SSRF...);
 *      does a payload marker for that technique appear in an evidence line that mentions
 *      THE SAME endpoint? A plain GET does not support "SQLi was tested here".
 *
 * Techniques that cannot be proven by a payload string (IDOR, CSRF, takeover) are reported
 * as `unverifiable` rather than silently passing -- an honest "I cannot check this" beats
 * a false green.
 *
 * EVIDENCE REQUIREMENT: point this at the hunt journal or recon items, which contain
 * request lines with URLs. Raw response captures contain no request lines and will make
 * every claim look unsupported.
 */

import { readFile, readdir, stat } from "node:fs/promises";
import { join, extname } from "node:path";

export const name = "claim-audit";
export const inject = ["tools"];

/** Verbs/phrases that turn a sentence into an assertion about an endpoint. */
const ASSERTION_RE =
  /\b(no|none|not|never|without|tested|verified|checked|confirmed|found|failed|secure|blocked|unaffected|resistant|absent|clean|vulnerable|exploitable|injectable)\b/i;

const METHOD_URL_RE =
  /\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?:\/\/[^\s`"')\]]+|\/[A-Za-z0-9_\-./{}:%*]+)/g;

const URL_ONLY_RE = /https?:\/\/[^\s"'`<>)]+/g;

const TEXT_EXT = new Set([".json", ".jsonl", ".txt", ".md", ".log"]);

/**
 * Technique signatures. `claim` detects the technique in a report sentence; `markers`
 * detect the payload in an evidence line. Empty `markers` => unverifiable by string.
 */
export const TECHNIQUES = [
  {
    name: "sqli",
    claim: /\bsql\s*injection\b|\bsqli\b/i,
    markers: [/(^|[^a-z])'\s*(or|and)\b/i, /\bsleep\s*\(/i, /\bunion\s+select\b/i, /\bor\s+1\s*=\s*1\b/i, /information_schema/i, /benchmark\s*\(/i],
  },
  { name: "nosqli", claim: /\bnosql/i, markers: [/\$ne\b/, /\$gt\b/, /\$where\b/, /\$regex\b/] },
  {
    name: "xss",
    claim: /\bxss\b|cross[- ]site scripting/i,
    markers: [/<script/i, /\bonerror\s*=/i, /javascript:/i, /\balert\s*\(/i, /onload\s*=/i],
  },
  {
    name: "ssrf",
    claim: /\bssrf\b|server[- ]side request/i,
    markers: [/169\.254\.169\.254/, /metadata\.google/i, /file:\/\//i, /gopher:\/\//i, /dict:\/\//i],
  },
  {
    name: "traversal",
    claim: /path traversal|directory traversal|\blfi\b|local file inclusion/i,
    markers: [/\.\.\//, /%2e%2e/i, /etc\/passwd/i, /win\.ini/i, /php:\/\/filter/i],
  },
  { name: "ssti", claim: /\bssti\b|template injection/i, markers: [/\{\{\s*7\s*\*\s*7/, /\$\{\s*7\s*\*\s*7/, /<%=/, /\*\{\s*7\s*\*\s*7/] },
  { name: "xxe", claim: /\bxxe\b|xml external entity/i, markers: [/<!entity/i, /<!doctype[^>]*\[/i, /system\s+["']/i] },
  {
    name: "cmdi",
    claim: /command injection|\brce\b|remote code execution/i,
    markers: [/;\s*(id|whoami|cat\s)/i, /\|\s*(id|whoami)\b/i, /\$\(id\)/, /`id`/],
  },
  { name: "redirect", claim: /open redirect/i, markers: [/\/\/evil/i, /evil\./, /@evil/i, /redirect_uri=/i] },
  { name: "cors", claim: /\bcors\b/i, markers: [/origin:\s*https?:\/\/(evil|attacker)/i, /access-control-allow-origin/i] },
  { name: "csrf", claim: /\bcsrf\b/i, markers: [], unverifiable: "CSRF is proven by a cross-site PoC, not a payload string" },
  { name: "idor", claim: /\bidor\b|insecure direct object/i, markers: [], unverifiable: "IDOR is proven by comparing two identities, not a payload string" },
  { name: "takeover", claim: /subdomain takeover/i, markers: [], unverifiable: "takeover is proven by serving content, not a payload string" },
];

function pathOf(u) {
  let s = u.replace(/^https?:\/\//, "");
  const slash = s.indexOf("/");
  s = slash === -1 ? "/" : s.slice(slash);
  return s.split("?")[0].split("#")[0].replace(/\/+$/, "") || "/";
}

async function collectEvidence(paths) {
  const chunks = [];
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
    } else if (TEXT_EXT.has(extname(p).toLowerCase())) {
      files.push(p);
      try {
        chunks.push(await readFile(p, "utf8"));
      } catch {
        /* unreadable: skip */
      }
    }
  }
  for (const p of paths) await walk(p);
  return { text: chunks.join("\n"), files };
}

/**
 * Pure core, exported for offline testing. `report` and `evidenceText` are plain strings.
 */
export function auditClaims(report, evidenceText) {
  const evidenceLines = evidenceText.split("\n").filter((l) => l.trim());

  // Index evidence by the paths each line mentions, so a technique marker can be
  // correlated with the endpoint it was actually sent to.
  const pathsOfLine = (l) => {
    const out = new Set();
    for (const m of l.matchAll(METHOD_URL_RE)) out.add(pathOf(m[2]));
    for (const m of l.matchAll(URL_ONLY_RE)) out.add(pathOf(m[0]));
    return out;
  };
  const linesByPath = new Map();
  for (const l of evidenceLines) {
    for (const p of pathsOfLine(l)) {
      if (!linesByPath.has(p)) linesByPath.set(p, []);
      linesByPath.get(p).push(l);
    }
  }
  const allPaths = [...linesByPath.keys()];
  const pathSeen = (p) => allPaths.some((ep) => ep === p || ep.startsWith(p) || p.startsWith(ep));

  const claimed = new Map();
  for (const m of report.matchAll(METHOD_URL_RE)) {
    claimed.set(`${m[1].toUpperCase()} ${pathOf(m[2])}`, {
      method: m[1].toUpperCase(),
      path: pathOf(m[2]),
    });
  }

  const sentences = report
    .split(/\n|(?<=[.!?])\s+/)
    .map((s) => s.trim())
    .filter(Boolean);

  const claims = [];
  for (const s of sentences) {
    if (!ASSERTION_RE.test(s)) continue;
    const refs = [...s.matchAll(METHOD_URL_RE)].map((m) => ({
      method: m[1].toUpperCase(),
      path: pathOf(m[2]),
    }));
    if (refs.length === 0) continue;
    const techniques = TECHNIQUES.filter((t) => t.claim.test(s));

    for (const r of refs) {
      const endpoint = `${r.method} ${r.path}`;
      if (!pathSeen(r.path)) {
        claims.push({
          assertion: s.slice(0, 240),
          endpoint,
          status: "unsupported",
          reason: "NO request to this endpoint appears anywhere in the hunt evidence",
        });
        continue;
      }
      const related = linesByPath.get(r.path) || [];
      let flagged = false;
      for (const t of techniques) {
        if (t.markers.length === 0) {
          claims.push({
            assertion: s.slice(0, 240),
            endpoint,
            status: "unverifiable",
            technique: t.name,
            reason: `endpoint was requested, but ${t.name} cannot be verified from payload strings (${t.unverifiable})`,
          });
          continue;
        }
        const hasMarker = related.some((l) => t.markers.some((re) => re.test(l)));
        if (!hasMarker) {
          flagged = true;
          claims.push({
            assertion: s.slice(0, 240),
            endpoint,
            status: "unsupported",
            technique: t.name,
            reason: `claims ${t.name} testing here, but no ${t.name} payload marker appears in any evidence line for this endpoint`,
          });
        }
      }
      if (!flagged) {
        claims.push({
          assertion: s.slice(0, 240),
          endpoint,
          status: "supported",
          reason:
            techniques.length === 0
              ? "endpoint appears in the evidence"
              : "endpoint requested and the claimed technique's payload appears in evidence",
        });
      }
    }
  }

  const neverRequested = [...claimed.values()]
    .filter(({ path }) => !pathSeen(path))
    .map(({ method, path }) => `${method} ${path}`);

  const unsupported = claims.filter((c) => c.status === "unsupported");
  const unverifiable = claims.filter((c) => c.status === "unverifiable");
  return {
    claimed_endpoints: claimed.size,
    evidenced_paths: allPaths.length,
    claims: claims.slice(0, 200),
    unsupported_count: unsupported.length,
    unsupported: unsupported.slice(0, 100),
    unverifiable_count: unverifiable.length,
    unverifiable: unverifiable.slice(0, 50),
    endpoints_never_requested: [...new Set(neverRequested)].slice(0, 100),
    pass: unsupported.length === 0 && claimed.size > 0,
    note:
      "Point evidencePaths at the hunt journal or recon items (request lines with URLs). " +
      "Raw response captures alone contain no request lines and will look unsupported.",
  };
}

/** Endpoint references found in a report, for building a test plan. */
export function extractClaimedEndpoints(report) {
  const out = new Set();
  for (const m of report.matchAll(METHOD_URL_RE)) {
    out.add(`${m[1].toUpperCase()} ${pathOf(m[2])}`);
  }
  return [...out];
}

export function apply(ctx) {
  ctx.tools.register({
    name: "audit_report",
    description:
      "Check a report's endpoint claims against the hunt's own evidence. Flags (a) assertions about endpoints no request ever touched, and (b) claims of testing a technique (SQLi/XSS/SSRF...) where no payload marker for it appears in the evidence for that endpoint. Run before submitting any report, and before writing a 'no findings' SUMMARY. Reads local files only.",
    parameters: {
      type: "object",
      properties: {
        reportPath: { type: "string", description: "Path to the report markdown." },
        reportText: { type: "string", description: "Report text, if not using reportPath." },
        evidencePaths: {
          type: "string",
          description: "Files/directories holding hunt evidence (journal.jsonl, recon/, logs/), one per line.",
        },
      },
      required: ["evidencePaths"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      let report = args.reportText || "";
      if (!report && args.reportPath) {
        try {
          report = await readFile(args.reportPath, "utf8");
        } catch (e) {
          return JSON.stringify({ pass: false, error: `cannot read report: ${e.message}` });
        }
      }
      if (!report.trim()) return JSON.stringify({ pass: false, error: "no report text supplied" });

      const evPaths = String(args.evidencePaths || "")
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);
      const { text, files } = await collectEvidence(evPaths);
      if (!text.trim()) {
        return JSON.stringify({
          pass: false,
          error: "no readable evidence files found — cannot verify any claim",
          checked_paths: evPaths,
        });
      }
      return JSON.stringify({ evidence_files: files.length, ...auditClaims(report, text) });
    },
  });

  console.log("[claim-audit] registered: audit_report");
}
