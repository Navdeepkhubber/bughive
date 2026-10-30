/**
 * dsh-scope-intake — turn a program's scope and policy text into machine-checkable rules.
 *
 * WHY THIS EXISTS
 * Bug bounty scope pages are prose and tables, not data. The pipeline required an operator
 * to hand-write scope.txt, so exclusions and policy rules lived only in a human's head.
 * That is how a tool ends up submitting something the program forbids: XBOW reports being
 * "officially removed from a program that didn't allow automatic scanners".
 *
 * This parses scope/policy text into in-scope patterns, explicit exclusions, policy flags
 * and excluded vulnerability classes (in the vocabulary `triage_gate` uses), so a finding
 * in a forbidden class is killed before it is ever written up.
 *
 * Matching is SENTENCE-BASED and order-agnostic: policy prose says both "no DoS" and
 * "DoS is prohibited", and an earlier version of this file only handled the first form.
 *
 * Offline and deterministic. An LLM may refine it upstream; this is the part that can be
 * unit-tested and cannot hallucinate.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const name = "scope-intake";
export const inject = ["tools"];

const SUFFIX_RULES = loadSuffixRules();

function loadSuffixRules() {
  const fallback = {
    sld_tokens: ["ac", "co", "com", "edu", "go", "gob", "gov", "govt", "ne", "net", "or", "org"],
    au_slds: ["edu", "gov"],
    au_states: ["act", "nsw", "nt", "qld", "sa", "tas", "vic", "wa"],
    extra_suffixes: ["uk.com", "eu.com"],
  };
  try {
    const path = join(dirname(fileURLToPath(import.meta.url)), "../../scripts/pipeline/data/public-suffix-guards.json");
    const data = JSON.parse(readFileSync(path, "utf8"));
    return {
      sld_tokens: new Set((data.sld_tokens || fallback.sld_tokens).map((t) => String(t).toLowerCase())),
      au_slds: new Set((data.au_slds || []).map((t) => String(t).toLowerCase())),
      au_states: new Set((data.au_states || []).map((t) => String(t).toLowerCase())),
      extra_suffixes: [...(data.extra_suffixes || [])]
        .map((s) => String(s).toLowerCase().replace(/\.+$/, ""))
        .sort((a, b) => b.length - a.length),
    };
  } catch {
    return {
      sld_tokens: new Set(fallback.sld_tokens),
      au_slds: new Set(fallback.au_slds),
      au_states: new Set(fallback.au_states),
      extra_suffixes: fallback.extra_suffixes,
    };
  }
}

function hostLabels(host) {
  return String(host || "")
    .trim()
    .toLowerCase()
    .replace(/\.+$/, "")
    .split(".")
    .filter(Boolean);
}

/** Trailing public-suffix length. Mirrors scripts/pipeline/_scope.py. */
export function suffixLength(labels) {
  const n = labels.length;
  if (!n) return 0;
  const joined = labels.join(".");
  let best = 1;
  for (const suf of SUFFIX_RULES.extra_suffixes) {
    if (joined === suf || joined.endsWith(`.${suf}`)) {
      best = Math.max(best, suf.split(".").length);
      break;
    }
  }
  if (
    n >= 3 &&
    labels[n - 1] === "au" &&
    SUFFIX_RULES.au_slds.has(labels[n - 2]) &&
    SUFFIX_RULES.au_states.has(labels[n - 3])
  ) {
    best = Math.max(best, 3);
  }
  if (n >= 2 && labels[n - 1].length === 2 && SUFFIX_RULES.sld_tokens.has(labels[n - 2])) {
    best = Math.max(best, 2);
  }
  return best;
}

export function isPublicSuffix(host) {
  const labels = hostLabels(host);
  if (!labels.length || labels.some((label) => label.includes("*"))) return false;
  if (labels.length === 1) return true;
  return labels.length <= suffixLength(labels);
}

export function registrableDomain(host) {
  const labels = hostLabels(host);
  if (!labels.length || labels.some((label) => label.includes("*"))) return null;
  const sl = suffixLength(labels);
  if (labels.length <= sl) return null;
  return labels.slice(-(sl + 1)).join(".");
}

/**
 * Encode one extracted host without inventing a public-suffix root.
 *
 * `**.www.<host>` is the unsafe rewrite: enum_roots then slices the last two
 * labels and emits `co.jp` / `com.au`. Collapse that form to the named host.
 * "Host and its subdomains" is `*.<host>` (the private label stays in the
 * pattern). A bare public suffix is dropped. An explicit wildcard that is not
 * the www-rewrite is kept as written.
 */
export function encodeScopedHost(raw, { subdomains = false } = {}) {
  let h = String(raw || "").trim().toLowerCase().replace(/\.+$/, "");
  if (!h) return [];
  if (/^\*\*\.www\./.test(h)) {
    h = h.replace(/^\*\*\./, "");
    subdomains = true;
  }
  const concrete = h.replace(/^\*\*\./, "").replace(/^\*\./, "");
  if (!concrete || isPublicSuffix(concrete)) return [];
  if (h.includes("*")) return [h];
  const out = [h];
  // One label under the named host. Never `**.www.<host>` and never the bare
  // registrable domain — a VDP that lists www hosts does not authorize siblings.
  if (subdomains) out.push(`*.${h}`);
  return out;
}

const OUT_SECTION = /(out[\s-]*of[\s-]*scope|not[\s-]*in[\s-]*scope|excluded|prohibited)/i;
const IN_SECTION = /(in[\s-]*scope|scope\b|assets?|targets?|domains?)/i;

/**
 * Host-ish token: domain or wildcard.
 * NOTE: no leading \b — a word boundary cannot match between a space and `*`, so `\b`
 * silently dropped every `*.example.com` wildcard entry (caught by the offline test).
 */
const HOST_RE = /(?:\*\*\.|\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}/gi;

/** "and their subdomains" authorizes `*.<host>`. The word "domain" alone does not. */
const SUBDOMAIN_RE = /\b(sub-?domains?|and their subdomains|including subdomains)\b/i;

function lineHasHost(line) {
  HOST_RE.lastIndex = 0;
  const ok = HOST_RE.test(line);
  HOST_RE.lastIndex = 0;
  return ok;
}

/** Any phrasing that negates, restricts or excludes. */
const NEGATION_RE =
  /\b(no|not|never|disallow\w*|prohibit\w*|forbid\w*|exclude[sd]?|excluding|out[\s-]*of[\s-]*scope|not\s+accept\w*|won'?t\s+accept|declin\w*|unacceptable|forbidden|restricted)\b/i;

/**
 * Policies that restrict behaviour, plus the vulnerability classes they exclude outright.
 * `subject` is matched independently of `NEGATION_RE`, so word order is irrelevant.
 */
const POLICY_RULES = [
  {
    id: "automated-scanning",
    subject: /\b(automated|automatic|scanner|scanning|bots?)\b/i,
    excludes: [],
    note: "Automated scanning restricted — do not run volume tooling against this program.",
  },
  {
    id: "dos",
    subject: /\b(dos|denial[\s-]*of[\s-]*service|flood|stress[\s-]*test|resource exhaustion)\b/i,
    excludes: [],
    note: "DoS prohibited — keep request rates low and never amplify.",
  },
  {
    id: "no-disruption",
    subject: /\b(disrupt\w*|service degradation)\b/i,
    excludes: [],
    note: "No-disruption rule — select the low rate profile and proceed.",
  },
  {
    id: "critical-infrastructure",
    subject: /\b(critical[\s-]*infrastructure|emergency[\s-]*services?|life[\s-]*safety)\b/i,
    excludes: [],
    note: "Critical infrastructure — select the low rate profile and proceed.",
  },
  {
    id: "brute-force",
    subject: /\b(brute[\s-]*force|password guessing|credential stuffing)\b/i,
    excludes: [],
    note: "Brute force prohibited.",
  },
  {
    id: "social-engineering",
    subject: /\b(social engineering|phishing|pretext\w*|vishing)\b/i,
    excludes: [],
    note: "Social engineering prohibited.",
  },
  {
    id: "physical",
    subject: /\b(physical|on[\s-]*site|premises)\b/i,
    excludes: [],
    note: "Physical testing prohibited.",
  },
  {
    id: "cache-poisoning",
    subject: /\b(cache[\s-]*poison\w*|web cache deception)\b/i,
    excludes: ["cache-poisoning"],
    note: "Cache poisoning excluded by policy.",
  },
  {
    id: "self-xss",
    subject: /\bself[\s-]*xss\b/i,
    excludes: ["xss"],
    note: "Self-XSS excluded.",
  },
  {
    id: "best-practice",
    subject: /\b(missing (security )?headers?|best practice|tls|ssl|cipher\w*|spf|dmarc|dkim|hsts)\b/i,
    excludes: [],
    note: "Header/TLS best-practice reports excluded.",
  },
  {
    id: "rate-limit-only",
    subject: /\brate[\s-]*limit\w*\b/i,
    excludes: [],
    note: "Missing-rate-limit-only reports excluded.",
  },
  {
    id: "third-party",
    subject: /\b(third[\s-]*part\w*|vendor|subprocessor)\b/i,
    excludes: [],
    note: "Third-party findings excluded.",
  },
  {
    id: "no-disclosure",
    subject: /\b(public disclosure|publish\w*|blog post)\b/i,
    excludes: [],
    note: "No public disclosure permitted.",
  },
];

/** Split into lines, tracking the scope section each line belongs to. */
export function sectionize(text) {
  const out = [];
  let mode = "unknown";
  let authorizeSubdomains = false;
  for (const raw of String(text || "").split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    // A host on the same line as a section heading must be kept. "subdomains"
    // contains "domains", so a one-line "www.example.co.jp and their subdomains"
    // used to be swallowed as an in-scope header and the host was lost.
    const hostLine = lineHasHost(line);
    // Headers update the sticky "and their subdomains" flag. A host that
    // shares a line with that phrase is data, not a header, so it must not
    // authorize wildcards for every later literal.
    if (OUT_SECTION.test(line) && line.length < 120 && !hostLine) {
      mode = "out";
      authorizeSubdomains = SUBDOMAIN_RE.test(line);
      continue;
    }
    if (IN_SECTION.test(line) && line.length < 120 && !OUT_SECTION.test(line) && !hostLine) {
      mode = "in";
      authorizeSubdomains = SUBDOMAIN_RE.test(line);
      continue;
    }
    out.push({
      line,
      mode,
      subdomains: authorizeSubdomains || SUBDOMAIN_RE.test(line),
    });
  }
  return out;
}

/** Split prose into sentences for order-agnostic policy matching. */
export function sentences(text) {
  return String(text || "")
    .split(/\n|(?<=[.!?])\s+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

export function parseProgramText(text) {
  const sections = sectionize(text);
  const inScope = new Set();
  const outScope = new Set();
  for (const { line, mode, subdomains } of sections) {
    HOST_RE.lastIndex = 0;
    for (const h of line.match(HOST_RE) || []) {
      for (const pattern of encodeScopedHost(h, { subdomains: Boolean(subdomains) })) {
        if (mode === "out") outScope.add(pattern);
        else inScope.add(pattern);
      }
    }
  }
  for (const h of outScope) inScope.delete(h);

  const policyFlags = [];
  const excludedClasses = new Set();
  for (const sentence of sentences(text)) {
    if (!NEGATION_RE.test(sentence)) continue;
    for (const rule of POLICY_RULES) {
      if (!rule.subject.test(sentence)) continue;
      if (policyFlags.some((f) => f.id === rule.id)) continue;
      policyFlags.push({ id: rule.id, matched: sentence.slice(0, 160), note: rule.note });
      for (const c of rule.excludes) excludedClasses.add(c);
    }
  }

  return {
    in_scope: [...inScope].sort(),
    out_of_scope: [...outScope].sort(),
    policy_flags: policyFlags,
    excluded_classes: [...excludedClasses].sort(),
    note:
      "Deterministic extraction. Verify against the program page before relying on it; an " +
      "LLM pass should refine this and a human should confirm exclusions.",
  };
}

export function apply(ctx) {
  ctx.tools.register({
    name: "parse_program_scope",
    description:
      "Parse a bug-bounty program's scope/policy text into in-scope patterns, explicit exclusions, policy flags (automated scanning, DoS, brute force...) and excluded vulnerability classes that triage_gate can enforce. Sentence-based and order-agnostic, so both 'no DoS' and 'DoS is prohibited' are caught. Offline and deterministic.",
    parameters: {
      type: "object",
      properties: {
        text: { type: "string", description: "Program scope/policy text (paste the page contents)." },
        path: { type: "string", description: "Alternative: path to a file containing it." },
      },
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      let text = args.text || "";
      if (!text && args.path) {
        const { readFile } = await import("node:fs/promises");
        try {
          text = await readFile(args.path, "utf8");
        } catch (e) {
          return JSON.stringify({ error: `cannot read ${args.path}: ${e.message}` });
        }
      }
      if (!text.trim()) return JSON.stringify({ error: "no program text supplied" });
      return JSON.stringify(parseProgramText(text));
    },
  });

  ctx.tools.register({
    name: "scope_txt",
    description:
      "Render parsed scope as a scope.txt document for `run.sh init` — in-scope patterns with `!` exclusions.",
    parameters: {
      type: "object",
      properties: { text: { type: "string" }, path: { type: "string" } },
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      let text = args.text || "";
      if (!text && args.path) {
        const { readFile } = await import("node:fs/promises");
        try {
          text = await readFile(args.path, "utf8");
        } catch (e) {
          return JSON.stringify({ error: `cannot read ${args.path}: ${e.message}` });
        }
      }
      const p = parseProgramText(text);
      const lines = [...p.in_scope, ...p.out_of_scope.map((h) => `!${h}`)];
      return JSON.stringify({
        scope_txt: lines.join("\n"),
        in_scope: p.in_scope.length,
        excluded: p.out_of_scope.length,
        excluded_classes: p.excluded_classes,
        policy_flags: p.policy_flags,
      });
    },
  });

  console.log("[scope-intake] registered: parse_program_scope, scope_txt");
}
