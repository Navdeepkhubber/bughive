/**
 * dsh-triage-gate — the 7-Question Gate plus an identity question, mechanised.
 *
 * WHY THIS EXISTS
 * dsh-critical-gate gates report *submission* behind human approval, but nothing in the
 * pipeline encodes the decision of whether a finding is reportable at all. That decision
 * is where bounty hunters lose money: an agent that has spent hours on a finding is
 * biased toward reporting it, and "N/A" verdicts damage a researcher's validity ratio.
 *
 * This turns the triage checklist into a deterministic tool: every question must be
 * answered yes (a missing answer counts as no), and the title/impact text is checked
 * against the program's always-rejected list. One wrong answer blocks the report.
 *
 * A blocked report is demoted to a lead. The record, payload, and chain partners stay.
 * Nothing here deletes a candidate.
 *
 * Findings that are only valid WITH a chain must name that chain, otherwise they fail.
 * Question 8 applies only to identity/authz claims (IDOR, missing auth, privilege
 * change): which session found it, whether it reproduces anonymously, whether a second
 * account sees different data, and whether the credential was stale.
 *
 * Attribution: question order and the standalone/chain split follow public triage
 * practice. Written reference is Aetherdz/huntpack (MIT); the rows below are rewritten
 * for this repo and are not a copy of that text.
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

/** Q8 is asked only for identity/authz claims. A missing answer still counts as no. */
export const Q8 = [
  "q8Identity",
  "Which session found this, does it reproduce with no session, does a second account see different data, and was the credential stale?",
];

const IDENTITY_CLASS =
  /\bidor\b|insecure direct object|missing[- ]auth|auth(?:entication)? bypass|privilege escalation|privesc|broken access control/i;

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

/**
 * Standalone primitives that are not a report even when a chain is claimed.
 * DNS-only SSRF, self-XSS, and header-only notes have no demonstrated impact.
 */
export const HARD_DENY = [
  { test: /dns-only|dns only|ssrf dns/, why: "DNS-only SSRF shows no data access" },
  { test: /self-xss|self xss/, why: "self-XSS stays inside the attacker's own session" },
  {
    test: /missing (csp|hsts|x-frame-options|x-frame|spf|dkim|dmarc)|security header|headers-only|header-only|missing httponly|cookie flag|weak cipher/,
    why: "headers-only note has no exploit",
  },
];

/** Classes that are only valid when chained into a real impact. */
export const REQUIRES_CHAIN = [
  "open redirect",
  "clickjacking",
  "cors",
  "csrf",
  "rate limit",
  "ssrf",
  "host header",
  "subdomain takeover",
  "introspection",
];

/**
 * Standalone primitive → partner a report must actually show.
 * `partners` are matched against the chain description, not the bare hasChain flag.
 */
export const CHAIN_REQUIRED = [
  { standalone: "open redirect", partners: ["oauth", "redirect_uri", "account takeover", "ato"], result: "stolen authentication token" },
  { standalone: "clickjacking", partners: ["sensitive action", "state-changing", "state change"], result: "victim-triggered sensitive action" },
  { standalone: "cors", partners: ["credential", "exfil", "pii"], result: "credentialed cross-origin read" },
  { standalone: "csrf", partners: ["state change", "email change", "transfer", "password"], result: "cross-site state change" },
  { standalone: "rate limit", partners: ["otp", "brute", "account takeover", "ato"], result: "guessed secret accepted" },
  { standalone: "host header", partners: ["password reset", "reset link", "poison"], result: "poisoned password-reset link" },
  { standalone: "graphql introspection", partners: ["auth bypass", "mutation", "unauthorized"], result: "unauthorized mutation or field read" },
  { standalone: "introspection", partners: ["auth bypass", "mutation", "unauthorized"], result: "unauthorized mutation or field read" },
  { standalone: "subdomain takeover", partners: ["oauth", "session", "cookie"], result: "session or oauth compromise" },
  { standalone: "ssrf", partners: ["metadata", "internal", "file read", "cloud credential"], result: "internal or cloud data read" },
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

export function isIdentityClaim(text = "") {
  return IDENTITY_CLASS.test(String(text));
}

function mentions(blob, phrase) {
  const p = String(phrase || "").toLowerCase();
  if (!p) return false;
  if (p.includes(" ")) return blob.includes(p);
  return new RegExp(`(?:^|[^a-z0-9])${p}(?:[^a-z0-9]|$)`, "i").test(blob);
}

export function matchHardDeny(text = "") {
  const blob = String(text).toLowerCase();
  return HARD_DENY.find((row) => row.test.test(blob)) || null;
}

export function matchChainRequired(text = "") {
  const blob = String(text).toLowerCase();
  return CHAIN_REQUIRED.find((row) => blob.includes(row.standalone)) || null;
}

export function chainSatisfied(row, chainText, hasChain) {
  if (!row || !hasChain) return false;
  const blob = String(chainText || "").toLowerCase();
  return row.partners.some((p) => mentions(blob, p));
}

/**
 * Q8. Distinguishes IDOR (session A reads account B) from missing authentication
 * (no session at all) and from a stale credential. A missing record is a no.
 */
export function evaluateIdentity(text, answers = {}, identity = null) {
  const id = identity && typeof identity === "object" ? identity : null;
  const explicit = answers.q8Identity === true;
  if (!id && !explicit) {
    return {
      pass: false,
      classification: "unanswered",
      disposition: "lead",
      reason: "identity check unanswered (session, anonymous repro, cross-account, stale credential)",
    };
  }
  const stale = id?.staleCredential === true || id?.stale_credential === true;
  if (stale) {
    return {
      pass: false,
      classification: "stale-cred",
      disposition: "lead",
      reason: "stale credential; keep as a lead and retest with a fresh session",
    };
  }
  const anonymous = id?.anonymous === true || id?.anonymousRepro === true;
  const cross = id?.crossAccount === true || id?.cross_account === true;
  const pii = id?.otherUserPii === true || id?.other_user_pii === true;
  const same = id?.sameData === true || id?.same_data === true;
  const claimsIdor = /\bidor\b|insecure direct object/i.test(text);
  if (same) {
    return {
      pass: false,
      classification: "same-data",
      disposition: "lead",
      reason: "both identities received the same body",
    };
  }
  if (anonymous && claimsIdor) {
    return {
      pass: false,
      classification: "missing-auth",
      disposition: "lead",
      reclass: "missing-auth",
      reason: "anonymous repro is missing authentication, not IDOR",
    };
  }
  if (cross && pii && !anonymous) {
    return { pass: true, classification: "idor", disposition: "finding", reason: "one session read another account's data" };
  }
  if (anonymous && !claimsIdor) {
    return { pass: true, classification: "missing-auth", disposition: "finding", reason: "reproduced with no session" };
  }
  if (explicit && !id) {
    return { pass: true, classification: "asserted", disposition: "finding", reason: "identity question answered yes" };
  }
  return {
    pass: false,
    classification: "unclassified",
    disposition: "lead",
    reason: "cross-account differential not shown",
  };
}

/** Dual-session line that makes an IDOR claim checkable. Same digest or one session does not. */
export function idorIdentityRecord(event) {
  if (!event || event.kind !== "identity") return null;
  const tech = String(event.technique || "idor").toLowerCase();
  if (tech && tech !== "idor") return null;
  if (!event.session_a || !event.session_b || event.session_a === event.session_b) {
    return { ok: false, classification: "unanswered" };
  }
  if (event.stale_credential === true || event.staleCredential === true) {
    return { ok: false, classification: "stale-cred" };
  }
  if (event.anonymous === true) return { ok: false, classification: "missing-auth" };
  if (event.same_data === true || event.sameData === true) return { ok: false, classification: "same-data" };
  if (event.other_user_pii !== true && event.otherUserPii !== true) return { ok: false, classification: "no-pii" };
  if (!event.digest_a || !event.digest_b || event.digest_a === event.digest_b) {
    return { ok: false, classification: "same-data" };
  }
  return { ok: true, classification: "idor" };
}

export function chainHypothesesFor(findings = []) {
  const out = [];
  for (const f of findings) {
    const blob = `${f.class || ""} ${f.bugClass || ""} ${f.title || ""} ${f.impact || ""}`;
    if (matchHardDeny(blob)) continue;
    const row = matchChainRequired(blob);
    if (!row || f.hasChain === true) continue;
    out.push({
      source_id: f.id || null,
      standalone: row.standalone,
      partners: row.partners,
      result: row.result,
      hypothesis: `Keep ${row.standalone} as a lead and test whether it chains to ${row.result}`,
    });
  }
  return out;
}

/** Gate failure keeps the payload and names chain partners. It does not drop the record. */
export function demoteToLead(finding, reason, partners = []) {
  return {
    ...finding,
    disposition: "lead",
    previous_disposition: finding.disposition || "candidate",
    kept: true,
    demote_reason: reason,
    chain_partners: partners,
    payload: finding.payload,
  };
}

/**
 * Promote a lead when a sibling finding supplies its missing partner, or when the
 * same root marker is confirmed on another endpoint. The lead still needs its own
 * confirm signal — a sibling does not invent one.
 */
export function promoteLeads(leads = [], siblings = []) {
  const promoted = [];
  const still = [];
  for (const lead of leads) {
    const partners = lead.chain_partners || [];
    const siblingHit = siblings.some((s) => {
      const blob = `${s.class || ""} ${s.bugClass || ""} ${s.title || ""} ${s.impact || ""}`.toLowerCase();
      const partner = partners.some((p) => mentions(blob, p));
      const echo = lead.root && s.root && lead.root === s.root && (s.disposition === "confirm" || s.disposition === "finding");
      return partner || echo;
    });
    const selfReady = lead.confirm_signal === true || lead.matrix_result === "confirm";
    if (siblingHit && selfReady) {
      promoted.push({ ...lead, disposition: "finding", kept: true, promoted_by: "sibling" });
    } else {
      still.push(lead);
    }
  }
  return { promoted, still_leads: still };
}

export function reportEmissionDecision(finding = {}, chain = null) {
  const title = finding.title || "";
  const impact = finding.impact || "";
  const blob = `${title} ${impact} ${finding.class || ""} ${finding.bugClass || ""}`;
  const chainText = [
    typeof chain === "string" ? chain : JSON.stringify(chain || {}),
    finding.chain || "",
    title,
    impact,
  ].join(" ");
  const hasChain = Boolean(chain) || finding.hasChain === true || Boolean(finding.chain);
  if (finding.disposition === "lead") {
    return { emit: false, disposition: "lead", reason: finding.demote_reason || "already a lead", partners: finding.chain_partners || [] };
  }
  const hard = matchHardDeny(blob);
  if (hard) {
    return { emit: false, disposition: "lead", tag: "standalone_invalid", reason: hard.why, partners: [] };
  }
  const row = matchChainRequired(blob);
  if (row && !chainSatisfied(row, chainText, hasChain)) {
    const hypo = chainHypothesesFor([finding]);
    return {
      emit: false,
      disposition: "lead",
      tag: "needs_chain",
      reason: `${row.standalone} is not reportable until it shows ${row.result}`,
      partners: row.partners,
      chain_hypotheses: hypo,
    };
  }
  return { emit: true, disposition: "finding" };
}

export function runGate({ title, impact, answers = {}, hasChain = false, chain = "", programExclusions = [], identity = null }) {
  const failures = [];
  const warnings = [];
  const normalized = {};

  for (const [key, text] of QUESTIONS) {
    const val = answers[key] === true;
    normalized[key] = val;
    if (!val) failures.push(`${key}: NO -- ${text}`);
  }

  const blob = `${title || ""} ${impact || ""}`.toLowerCase();
  let identityResult = null;
  if (isIdentityClaim(`${title || ""} ${impact || ""}`) || answers.q8Identity !== undefined || identity) {
    identityResult = evaluateIdentity(`${title || ""} ${impact || ""}`, answers, identity);
    normalized.q8Identity = identityResult.pass === true;
    if (!identityResult.pass) failures.push(`q8Identity: NO -- ${identityResult.reason}`);
  }

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

  const hard = matchHardDeny(blob);
  const chainRow = matchChainRequired(`${title || ""} ${impact || ""}`);
  const chainText = `${chain || ""} ${title || ""} ${impact || ""}`;
  let tag = null;
  if (hard) {
    tag = "standalone_invalid";
    failures.push(`hard-deny: ${hard.why}`);
  } else if (hits.length) {
    const needsChain = Boolean(chainRow) || REQUIRES_CHAIN.some((c) => blob.includes(c));
    const shown = chainRow ? chainSatisfied(chainRow, chainText, hasChain) : hasChain;
    if (needsChain && !shown) {
      tag = "needs_chain";
      failures.push(`always-rejected class without a demonstrated chain: ${hits.join("; ")}`);
    } else if (!needsChain) {
      tag = "standalone_invalid";
      failures.push(`always-rejected class: ${hits.join("; ")}`);
    } else {
      warnings.push(`always-rejected class, chain claimed: ${hits.join("; ")}`);
    }
  }
  if (hasChain) warnings.push(`chain claimed: ${chain || "unspecified"}`);

  const passed = failures.length === 0;
  return {
    passed,
    failures,
    warnings,
    answers: normalized,
    cvss: cvssHint(title, impact),
    verdict: passed ? "PASS — all 7 questions yes" : "KILL — do not report",
    disposition: passed ? "finding" : "lead",
    kept: true,
    tag,
    identity: identityResult,
    chain_hypotheses: !passed && tag === "needs_chain" ? chainHypothesesFor([{ title, impact }]) : [],
  };
}

export function apply(ctx) {
  ctx.tools.register({
    name: "triage_gate",
    description:
      "Run the 7-Question Gate over a candidate finding before any report is written. Every question must be answered true; a missing answer counts as NO. Identity claims also answer Q8 (session, anonymous repro, cross-account, stale credential). Checks the never-submit list, hard-denies DNS-only SSRF, self-XSS, and headers-only notes, and requires a demonstrated chain partner before a chain-only class can pass. A failing gate demotes to a lead (kept: true); it does not delete the candidate.",
    parameters: {
      type: "object",
      properties: {
        title: { type: "string", description: "Finding title in the form '[Class] in [endpoint] allows [actor] to [impact]'." },
        impact: { type: "string", description: "Concrete impact statement." },
        answers: { type: "string", description: `JSON object with all 7 keys: ${QUESTIONS.map(([k]) => k).join(", ")}. Add q8Identity for identity claims.` },
        hasChain: { type: "boolean", description: "True only if a working chain was demonstrated end to end." },
        chain: { type: "string", description: "Description of the demonstrated chain. Must name the required partner." },
        identity: {
          type: "string",
          description:
            "JSON {session, anonymous, crossAccount, staleCredential, otherUserPii, sameData} for IDOR versus missing-auth.",
        },
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
      let identity = null;
      if (args.identity) {
        try {
          identity = JSON.parse(args.identity);
        } catch (e) {
          return JSON.stringify({
            passed: false,
            kept: true,
            disposition: "lead",
            failures: [`identity is not valid JSON: ${e.message}`],
            verdict: "KILL — malformed gate input",
          });
        }
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
        identity,
      });
      return JSON.stringify({ title: args.title, ...res });
    },
  });

  ctx.tools.register({
    name: "promote_leads",
    description:
      "Promote demoted leads when a sibling finding supplies the missing chain partner or the same root marker is confirmed elsewhere. Leads without their own confirm signal stay leads.",
    parameters: {
      type: "object",
      properties: {
        leads: { type: "string", description: "JSON array of lead records." },
        siblings: { type: "string", description: "JSON array of sibling findings." },
      },
      required: ["leads"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      let leads;
      let siblings = [];
      try {
        leads = JSON.parse(args.leads);
        if (args.siblings) siblings = JSON.parse(args.siblings);
        if (!Array.isArray(leads) || !Array.isArray(siblings)) throw new Error("expected arrays");
      } catch (e) {
        return JSON.stringify({ error: `leads/siblings must be JSON arrays: ${e.message}` });
      }
      return JSON.stringify(promoteLeads(leads, siblings));
    },
  });

  console.log("[triage-gate] registered: triage_gate, promote_leads");
}
