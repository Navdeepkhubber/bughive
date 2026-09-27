/**
 * dsh-triage-gate — the 7-Question Gate, mechanised.
 *
 * WHY THIS EXISTS
 * dsh-critical-gate gates report *submission* behind human approval, but nothing in the
 * pipeline encodes the decision of whether a finding is reportable at all. That decision
 * is where bounty hunters lose money: an agent that has spent hours on a finding is
 * biased toward reporting it, and "N/A" verdicts damage a researcher's validity ratio.
 *
 * This turns the triage checklist into a deterministic tool: every question must be
 * answered yes (a missing answer counts as no), and the title/impact text is checked
 * against the program's always-rejected list. One wrong answer kills the finding.
 *
 * Findings that are only valid WITH a chain must declare `hasChain: true` and a
 * description, otherwise they fail.
 */

export const name = "triage-gate";
export const inject = ["tools"];

export const QUESTIONS = [
  ["q1Reproducible", "Can an attacker use this RIGHT NOW with a copy-pasteable HTTP request?"],
  ["q2ImpactAccepted", "Is the impact on the program's accepted impact list?"],
  ["q3InScope", "Is the root cause in an in-scope asset (exact host verified)?"],
  ["q4NoPrivilegedAccess", "Does it avoid requiring privileged access an attacker cannot realistically get?"],
  ["q5NotKnown", "Is it NOT already documented/accepted behaviour or a known duplicate?"],
  ["q6ProvenImpact", "Can you prove impact beyond 'technically possible' (real data or damage shown)?"],
  ["q7NotAlwaysRejected", "Is it NOT on the always-rejected list (or does it have a working chain)?"],
];

/** Keyword -> why it is usually rejected. Checked against title + impact. */
export const NEVER_SUBMIT = {
  "missing csp": "security-header best practice, no exploit",
  "missing hsts": "security-header best practice, no exploit",
  "missing x-frame": "security-header best practice, no exploit",
  "missing spf": "email best practice, no exploit",
  "missing dkim": "email best practice, no exploit",
  "missing dmarc": "email best practice, no exploit",
  "security header": "best practice, no exploit",
  "graphql introspection": "introspection alone is not a vulnerability",
  "version disclosure": "banner disclosure without a working exploit",
  "banner disclosure": "banner disclosure without a working exploit",
  clickjacking: "invalid without a sensitive-action PoC",
  tabnabbing: "no demonstrable impact",
  "csv injection": "invalid without demonstrated code execution",
  "cors wildcard": "invalid without a credentialed exfiltration PoC",
  "logout csrf": "no meaningful impact",
  "self-xss": "only affects the attacker's own session",
  "open redirect": "invalid alone; needs an ATO or OAuth chain",
  "ssrf dns": "DNS-only callback is not impact",
  "dns-only": "DNS-only callback is not impact",
  "host header injection": "invalid alone; needs password-reset poisoning",
  "rate limit": "missing rate limiting alone is not payable",
  "unhandled exception": "500 without leakage or demonstrated impact",
  "http 500": "500 without leakage or demonstrated impact",
  "internal ip": "internal IP disclosure alone",
  "mixed content": "no demonstrable impact",
  "weak cipher": "TLS configuration best practice",
  "cookie flag": "missing HttpOnly/Secure alone",
  autocomplete: "no demonstrable impact",
  "session not invalidated": "logout behaviour alone",
  "concurrent session": "policy preference, not a vulnerability",
  "best practice": "programs explicitly reject best-practice reports",
  "missing httponly": "missing HttpOnly alone",
};

/** Classes that are only valid when chained into a real impact. */
export const REQUIRES_CHAIN = [
  "open redirect",
  "clickjacking",
  "cors",
  "csrf",
  "rate limit",
  "ssrf",
  "host header",
  "self-xss",
  "subdomain takeover",
  "introspection",
];

/** Rough CVSS 3.1 hint. Deliberately conservative -- never inflate severity. */
export function cvssHint(title = "", impact = "") {
  const t = `${title} ${impact}`.toLowerCase();
  if (/rce|remote code execution|command injection/.test(t))
    return { score: 9.8, severity: "Critical", rationale: "code execution on the server" };
  if (/auth bypass|authentication bypass|admin takeover|privilege escalation/.test(t))
    return { score: 9.8, severity: "Critical", rationale: "auth/privilege boundary crossed" };
  if (/ssrf.*metadata|cloud metadata/.test(t))
    return { score: 9.1, severity: "Critical", rationale: "cloud credential access via SSRF" };
  if (/sql injection|sqli/.test(t))
    return { score: 8.6, severity: "High", rationale: "database read/write" };
  if (/idor|insecure direct object/.test(t) && /write|delete|modify|update/.test(t))
    return { score: 7.5, severity: "High", rationale: "cross-user write" };
  if (/idor|insecure direct object/.test(t) && /pii|personal|credential|password/.test(t))
    return { score: 6.5, severity: "Medium", rationale: "cross-user read of sensitive data" };
  if (/stored xss/.test(t))
    return { score: 8.8, severity: "High", rationale: "stored XSS" };
  if (/xss/.test(t))
    return { score: 5.4, severity: "Medium", rationale: "reflected/DOM XSS" };
  return {
    score: null,
    severity: "unscored",
    rationale: "no confident match -- score manually with CVSS 3.1",
  };
}

export function runGate({ title, impact, answers = {}, hasChain = false, chain = "", programExclusions = [] }) {
  const failures = [];
  const warnings = [];
  const normalized = {};

  for (const [key, text] of QUESTIONS) {
    const val = answers[key] === true;
    normalized[key] = val;
    if (!val) failures.push(`${key}: NO -- ${text}`);
  }

  const blob = `${title || ""} ${impact || ""}`.toLowerCase();

  // Program policy exclusions (from scope-intake): a class the program refuses is not
  // reportable regardless of how good the evidence is. This is the check that keeps a
  // submission out of the "removed from the program" bucket.
  for (const ex of programExclusions) {
    const e = String(ex).toLowerCase().trim();
    if (!e) continue;
    if (blob.includes(e) || blob.includes(e.replace(/-/g, " "))) {
      failures.push(`program policy excludes class "${ex}" — not reportable on this program`);
    }
  }

  const hits = Object.entries(NEVER_SUBMIT)
    .filter(([kw]) => blob.includes(kw))
    .map(([kw, why]) => `${kw} (${why})`);

  if (hits.length) {
    const needsChain = REQUIRES_CHAIN.some((c) => blob.includes(c));
    if (needsChain && !hasChain) {
      failures.push(`always-rejected class without a demonstrated chain: ${hits.join("; ")}`);
    } else if (!needsChain) {
      failures.push(`always-rejected class: ${hits.join("; ")}`);
    } else {
      warnings.push(`always-rejected class, chain claimed: ${hits.join("; ")}`);
    }
  }
  if (hasChain) warnings.push(`chain claimed: ${chain || "unspecified"}`);

  return {
    passed: failures.length === 0,
    failures,
    warnings,
    answers: normalized,
    cvss: cvssHint(title, impact),
    verdict: failures.length === 0 ? "PASS — all 7 questions yes" : "KILL — do not report",
  };
}

export function apply(ctx) {
  ctx.tools.register({
    name: "triage_gate",
    description:
      "Run the 7-Question Gate over a candidate finding before any report is written. Every question must be answered true; a missing answer counts as NO. Also checks the always-rejected keyword list and returns a conservative CVSS hint. A failing gate means: do not report.",
    parameters: {
      type: "object",
      properties: {
        title: { type: "string", description: "Finding title in the form '[Class] in [endpoint] allows [actor] to [impact]'." },
        impact: { type: "string", description: "Concrete impact statement." },
        answers: { type: "string", description: `JSON object with all 7 keys: ${QUESTIONS.map(([k]) => k).join(", ")}.` },
        hasChain: { type: "boolean", description: "True only if a working chain was demonstrated end to end." },
        chain: { type: "string", description: "Description of the demonstrated chain." },
        programExclusions: {
          type: "string",
          description:
            "Comma-separated classes the program excludes (from parse_program_scope's excluded_classes). A match fails the gate regardless of evidence.",
        },
      },
      required: ["title", "answers"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      let answers;
      try {
        answers = JSON.parse(args.answers);
      } catch (e) {
        return JSON.stringify({
          passed: false,
          failures: [`answers is not valid JSON: ${e.message}`],
          verdict: "KILL — malformed gate input",
        });
      }
      const programExclusions = String(args.programExclusions || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const res = runGate({
        title: args.title,
        impact: args.impact || "",
        answers,
        hasChain: args.hasChain === true,
        chain: args.chain || "",
        programExclusions,
      });
      return JSON.stringify({ title: args.title, ...res });
    },
  });

  console.log("[triage-gate] registered: triage_gate");
}
