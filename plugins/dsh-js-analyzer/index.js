/**
 * dsh-js-analyzer — deterministic security analysis of JS/HTML assets.
 *
 * WHY THIS EXISTS
 * `recon-07-js-analysis` shipped as a stub (`count: 0, "notes":["stub"]`), so the pipeline
 * collected JS bundles and never looked inside them. In practice that is where the highest
 * -value leads live: client-side authorisation decisions, redirect allowlists that may be
 * enforced ONLY in the browser, postMessage handlers without origin checks, DOM XSS sinks,
 * baked-in endpoints the crawler never found, and committed secrets.
 *
 * Real example this rule set is built to catch: a bundle contained
 *   const TRUSTED_REDIRECT_ORIGINS = JSON.parse(meta["trusted_redirect_origins"].content)
 *   ... originMatchesPattern(parsed.origin)   // wildcard: https://*.example.com
 * i.e. the redirect allowlist is validated in JavaScript. Two questions follow immediately
 * and neither is answerable by reading the file: does the SERVER enforce it, and does the
 * wildcard admit a subdomain an attacker could take over? Those become leads.
 *
 * Output is LEADS, not vulnerabilities. Every hit carries a `next_step` describing the
 * request that would confirm or kill it.
 */

import { readFile, readdir, stat } from "node:fs/promises";
import { join, extname } from "node:path";

export const name = "js-analyzer";
export const inject = ["tools"];

const SCANNABLE = new Set([".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".html", ".htm", ".json", ".map"]);
const MAX_FILE_BYTES = 8 * 1024 * 1024;

/** Pattern rules. `re` is matched per line. */
export const RULES = [
  {
    id: "redirect-allowlist",
    severity: "high",
    title: "Redirect allowlist / trusted-origin list present",
    re: /trusted[_-]?(redirect|origin)|redirect[_-]?(allowlist|whitelist|origins?)|allowed[_-]?origins?|originMatchesPattern|validateSameOrigin|isTrustedOrigin/i,
    next_step:
      "Determine whether the SERVER enforces this allowlist or only the browser does. Send the redirect parameter directly with an off-allowlist value and inspect the Location header. If the wildcard admits any subdomain, check subdomain takeover on that parent.",
  },
  {
    id: "redirect-param",
    severity: "medium",
    title: "Redirect-style parameter referenced",
    re: /[?&](r|url|next|redirect|redirect_uri|return|returnUrl|continue|dest|target|to)=/i,
    next_step:
      "Test open redirect on each parameter, including //host, /\\host, https://expected@attacker, and URL-encoded variants. Only reportable chained to ATO/OAuth token theft.",
  },
  {
    id: "client-side-authz",
    severity: "high",
    title: "Authorization decision appears to be client-side",
    re: /(isAdmin|is_admin|canEdit|canDelete|hasPermission|checkRole|role\s*===|userRole|is_superuser|canView|canLink|canUnlink)/,
    next_step:
      "Server-side authorization must be tested directly. Replay the privileged action with a lower-privileged identity; if the server trusts the client's decision, this is a privilege escalation.",
  },
  {
    id: "dom-xss-sink",
    severity: "medium",
    title: "DOM XSS sink",
    re: /\.innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML|document\.write\(|dangerouslySetInnerHTML/,
    next_step:
      "Trace whether the sink receives attacker-controlled data (URL fragment, postMessage, API response). Confirm execution, not just reflection.",
  },
  {
    id: "code-exec",
    severity: "medium",
    title: "Dynamic code execution primitive",
    re: /\beval\s*\(|new\s+Function\s*\(|setTimeout\s*\(\s*["'`]|setInterval\s*\(\s*["'`]/,
    next_step: "Check whether any input reaching this primitive is attacker-controlled.",
  },
  {
    id: "postmessage",
    severity: "medium",
    title: "postMessage / message listener",
    re: /addEventListener\s*\(\s*["'`]message["'`]|onmessage\s*=|\.postMessage\s*\(/,
    next_step:
      "Check for a missing or weak event.origin check in the handler, and whether the message content reaches a sink. Cross-origin postMessage without an origin check is exploitable.",
  },
  {
    id: "hardcoded-secret",
    severity: "high",
    title: "Possible hardcoded credential or key",
    re: /(api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY)\s*[:=]\s*["'`][A-Za-z0-9_\-./+=]{12,}/i,
    next_step:
      "Verify the credential is live before reporting: use it against the service it belongs to and show what it grants. An unverified key is not a finding.",
  },
  {
    id: "aws-credential",
    severity: "high",
    title: "AWS key identifier pattern",
    re: /AKIA[0-9A-Z]{16}/,
    next_step: "Check scope and whether the key is live (aws sts get-caller-identity with --no-sign-request omitted).",
  },
  {
    id: "debug-flag",
    severity: "medium",
    title: "Debug / bypass flag",
    re: /(debug|test|skip[_-]?(auth|csfr|csrf)|bypass[_-]?(auth|security)|disable[_-]?(auth|security|csrf))\s*[:=]\s*(true|1|["'`]?(true|on|yes))/i,
    next_step: "Check whether the flag is honoured server-side (query param, header, cookie) and what it disables.",
  },
  {
    id: "insecure-endpoint",
    severity: "low",
    title: "Absolute http:// endpoint",
    re: /["'`]http:\/\/[a-z0-9.-]+/i,
    next_step: "Check for mixed-content-dependent behaviour or an injectable host.",
  },
  {
    id: "sourcemap",
    severity: "low",
    title: "Source map reference",
    re: /sourceMappingURL=/,
    next_step: "If the .map is fetchable it exposes original source, comments and sometimes secrets.",
  },
  {
    id: "internal-host",
    severity: "medium",
    title: "Internal / non-production hostname",
    re: /["'`]https?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|[a-z0-9.-]*\.(?:internal|local|corp|intranet))[:\/]/i,
    next_step: "Look for an SSRF or proxy path that reaches it, or a debug surface exposing it.",
  },
  {
    id: "graphql",
    severity: "medium",
    title: "GraphQL endpoint referenced",
    re: /["'`]\/[a-z0-9_\/-]*graphql[a-z0-9_\/-]*["'`]/i,
    next_step: "Try introspection; if enabled, enumerate mutations and test field-level authorization.",
  },
  {
    id: "jwt-handling",
    severity: "medium",
    title: "JWT handling in client",
    re: /\b(jwt|jsonwebtoken|jose)\b|alg\s*[:=]\s*["'`](none|HS256)/i,
    next_step: "Check for alg=none acceptance, weak HMAC secrets, or a missing signature check server-side.",
  },
  {
    id: "dangerous-comment",
    severity: "low",
    title: "Security-relevant TODO/FIXME/HACK",
    re: /(TODO|FIXME|HACK|XXX)[^\n]{0,80}(auth|security|csrf|token|permission|validate|sanitiz|escape|hardcod)/i,
    next_step: "Read the surrounding code; a known-unfinished security control is a strong lead.",
  },
];

/** Endpoint-ish strings worth adding to the inventory. */
const URL_RE = /["'`]((?:https?:\/\/[^\s"'`<>]{4,200})|(?:\/[a-zA-Z0-9_][a-zA-Z0-9_\-./{}$:]{2,120}))["'`]/g;

function contextOf(line, match) {
  const i = Math.max(0, line.indexOf(match) - 60);
  return line.slice(i, i + 160).trim();
}

async function collectFiles(targets) {
  const out = [];
  for (const t of targets) {
    let st;
    try {
      st = await stat(t);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      const entries = await readdir(t, { withFileTypes: true });
      for (const e of entries) {
        const p = join(t, e.name);
        if (e.isDirectory()) out.push(...(await collectFiles([p])));
        else if (SCANNABLE.has(extname(e.name).toLowerCase())) out.push(p);
      }
    } else if (SCANNABLE.has(extname(t).toLowerCase())) {
      out.push(t);
    }
  }
  return out;
}

/** Pure analysis over a {path: text} map. Exported for offline testing. */
export function analyzeSources(sources, { minSeverity = "low" } = {}) {
  const rank = { low: 1, medium: 2, high: 3 };
  const findings = [];
  const endpoints = new Set();

  for (const [file, text] of Object.entries(sources)) {
    const lines = text.split("\n");
    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      if (line.length > 4000) continue; // skip minified mega-lines for rule matching
      for (const rule of RULES) {
        if (rank[rule.severity] < rank[minSeverity]) continue;
        const m = line.match(rule.re);
        if (m) {
          findings.push({
            rule: rule.id,
            severity: rule.severity,
            title: rule.title,
            file,
            line: i + 1,
            match: m[0].slice(0, 160),
            context: contextOf(line, m[0]),
            next_step: rule.next_step,
          });
        }
      }
    }
    if (text.length <= MAX_FILE_BYTES) {
      for (const m of text.matchAll(URL_RE)) {
        const v = m[1];
        if (v.length > 3 && !/\.(png|jpe?g|svg|gif|woff2?|ttf|eot|ico|css)$/i.test(v)) endpoints.add(v);
      }
    }
  }

  // Deduplicate identical rule hits on the same line.
  const seen = new Set();
  const deduped = findings.filter((f) => {
    const k = `${f.rule}|${f.file}|${f.line}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });

  const bySeverity = {};
  const byRule = {};
  for (const f of deduped) {
    bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    byRule[f.rule] = (byRule[f.rule] || 0) + 1;
  }

  return {
    findings: deduped,
    by_severity: bySeverity,
    by_rule: byRule,
    endpoints: [...endpoints].sort(),
    files_scanned: Object.keys(sources).length,
  };
}

export function apply(ctx, config = {}) {
  const cfg = { maxFiles: 400, minSeverity: "low", ...config };

  ctx.tools.register({
    name: "analyze_js",
    description:
      "Statically analyse local JS/HTML/JSON bundles for security-relevant leads: client-side redirect allowlists, client-side authorization, DOM XSS sinks, postMessage handlers, hardcoded secrets, debug flags, internal hosts, GraphQL endpoints and more. Returns leads with a suggested next request, plus an extracted endpoint list. Reads local files only — sends no traffic.",
    parameters: {
      type: "object",
      properties: {
        paths: {
          type: "string",
          description: "Files or directories to scan, one per line (or comma-separated).",
        },
        minSeverity: { type: "string", enum: ["low", "medium", "high"], description: "Minimum severity to report (default low)." },
      },
      required: ["paths"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const targets = String(args.paths || "")
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);
      if (targets.length === 0) {
        return JSON.stringify({ error: "no paths supplied", findings: [] });
      }
      const files = (await collectFiles(targets)).slice(0, cfg.maxFiles);
      const sources = {};
      for (const f of files) {
        try {
          const st = await stat(f);
          if (st.size > MAX_FILE_BYTES) continue;
          sources[f] = await readFile(f, "utf8");
        } catch {
          /* unreadable file: skip, never fail the whole scan */
        }
      }
      const res = analyzeSources(sources, {
        minSeverity: args.minSeverity || cfg.minSeverity,
      });
      // Keep the returned payload bounded so it stays cheap to read.
      return JSON.stringify({
        ...res,
        findings: res.findings.slice(0, 300),
        endpoints: res.endpoints.slice(0, 300),
        truncated: res.findings.length > 300 || res.endpoints.length > 300,
      });
    },
  });

  console.log("[js-analyzer] registered: analyze_js (", RULES.length, "rules )");
}
