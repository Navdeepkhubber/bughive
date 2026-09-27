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

export const name = "scope-intake";
export const inject = ["tools"];

const OUT_SECTION = /(out[\s-]*of[\s-]*scope|not[\s-]*in[\s-]*scope|excluded|prohibited)/i;
const IN_SECTION = /(in[\s-]*scope|scope\b|assets?|targets?|domains?)/i;

/**
 * Host-ish token: domain or wildcard.
 * NOTE: no leading \b — a word boundary cannot match between a space and `*`, so `\b`
 * silently dropped every `*.example.com` wildcard entry (caught by the offline test).
 */
const HOST_RE = /(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}/gi;

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
  for (const raw of String(text || "").split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    if (OUT_SECTION.test(line) && line.length < 120) {
      mode = "out";
      continue;
    }
    if (IN_SECTION.test(line) && line.length < 120 && !OUT_SECTION.test(line)) {
      mode = "in";
      continue;
    }
    out.push({ line, mode });
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
  for (const { line, mode } of sections) {
    for (const h of line.match(HOST_RE) || []) {
      const clean = h.toLowerCase().replace(/\.$/, "");
      if (mode === "out") outScope.add(clean);
      else inScope.add(clean);
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
      });
    },
  });

  console.log("[scope-intake] registered: parse_program_scope, scope_txt");
}
