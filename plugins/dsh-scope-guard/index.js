/**
 * dsh-scope-guard — wildcard-aware scope enforcement.
 *
 * WHY THIS EXISTS
 * The bounty pipeline's scope lists are wildcard-based (e.g. `g-*.0.threema.ch`,
 * `safe-*.threema.ch`). The scope check in dsh-fp-filter compares hosts with
 * `===` / `endsWith`, so a wildcard entry can never match — meaning a scope
 * containing only wildcards yields "not in scope" for every real host, and the
 * guard silently does nothing. Touching an out-of-scope asset voids the safe
 * harbor, so this is the most safety-critical check in the pipeline.
 *
 * SEMANTICS
 *   `*`  matches exactly one DNS label (never crosses a dot)
 *   `**` matches one or more labels
 *   `!pattern` excludes (evaluated before includes; exclusion always wins)
 *   `#` comments and blank lines ignored
 * Default is DENY: a host must match an include and no exclude.
 *
 * Pure functions are exported so other plugins and scripts can reuse the matcher
 * instead of re-implementing it (`scopeAllows`, `parseScope`).
 */

export const name = "scope-guard";
export const inject = ["tools"];

/** Escape a host for literal regex use. */
function esc(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Translate one scope pattern into an anchored RegExp.
 * `*` -> one label, `**` -> one or more labels.
 */
export function patternToRegex(pattern) {
  const p = String(pattern || "").trim().toLowerCase().replace(/\.+$/, "");
  let out = "";
  for (let i = 0; i < p.length; i += 1) {
    const ch = p[i];
    if (ch === "*") {
      if (p[i + 1] === "*") {
        out += ".+";
        i += 1;
      } else {
        out += "[^.]+";
      }
    } else {
      out += esc(ch);
    }
  }
  return new RegExp(`^${out}$`);
}

/**
 * Parse a scope document into include/exclude patterns.
 * Accepts newline- or comma-separated text; `!` prefix excludes.
 */
export function parseScope(text) {
  const include = [];
  const exclude = [];
  // A `#` comment runs to end of LINE, not to the next comma, so comments are
  // stripped per line BEFORE the comma split. Splitting first (the original
  // behaviour) promoted the tail of any comment containing a comma into a bogus
  // scope pattern -- e.g. a scope comment `# covers *.a.com, *.b.com` produced
  // the include `*.b.com` from inside the comment. Must stay in lockstep with
  // parse_scope() in scripts/pipeline/_scope.py.
  for (const rawLine of String(text || "").split("\n")) {
    const line = rawLine.split("#")[0].trim();
    if (!line) continue;
    for (const rawEntry of line.split(",")) {
      let entry = rawEntry.trim();
      if (!entry) continue;
      entry = entry.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
      if (!entry) continue;
      if (entry.startsWith("!")) {
        const v = entry.slice(1).trim().toLowerCase();
        if (v) exclude.push(v);
      } else {
        include.push(entry.toLowerCase());
      }
    }
  }
  return { include: [...new Set(include)], exclude: [...new Set(exclude)] };
}

/** Normalise any target form (URL, host:port, IPv6 literal) to a bare host. */
export function normalizeHost(target) {
  let t = String(target || "").trim().toLowerCase();
  // Strip scheme. (Do NOT use split("//", 1)[1] -- with a limit of 1 that
  // returns ["https:"] and [1] is undefined, which silently produced
  // "undefined<host>". Caught by the offline scope-guard test.)
  const schemeIdx = t.indexOf("://");
  if (schemeIdx !== -1) t = t.slice(schemeIdx + 3);
  // Strip any userinfo (user:pass@host).
  const at = t.lastIndexOf("@");
  if (at !== -1) t = t.slice(at + 1);
  // Strip path, query and fragment.
  t = t.split("/")[0].split("?")[0].split("#")[0];
  // IPv6 literal in brackets, else host:port.
  if (t.startsWith("[")) {
    const end = t.indexOf("]");
    if (end !== -1) t = t.slice(1, end);
  } else if ((t.match(/:/g) || []).length === 1) {
    t = t.split(":")[0];
  }
  return t.replace(/\.+$/, "");
}

/**
 * Decide whether `host` is in scope for `scopeText`.
 * Returns { allowed, reason, matched }.
 */
export function scopeAllows(scopeText, host) {
  const target = normalizeHost(host);
  if (!target) return { allowed: false, reason: "empty target", matched: null };
  const { include, exclude } = parseScope(scopeText);
  if (include.length === 0 && exclude.length === 0) {
    return { allowed: false, reason: "scope document is empty (default deny)", matched: null };
  }
  // Exclusion always wins.
  for (const pat of exclude) {
    if (patternToRegex(pat).test(target)) {
      return { allowed: false, reason: `excluded by pattern "${pat}"`, matched: pat };
    }
  }
  for (const pat of include) {
    if (patternToRegex(pat).test(target)) {
      return { allowed: true, reason: `in scope via "${pat}"`, matched: pat };
    }
  }
  return { allowed: false, reason: "no include pattern matched (default deny)", matched: null };
}

export function apply(ctx) {
  ctx.tools.register({
    name: "scope_check",
    description:
      "Check whether a target host is within a wildcard-aware scope document. Handles `*` (one label), `**` (many labels), `!` exclusions and comments. Default deny.",
    parameters: {
      type: "object",
      properties: {
        scope: { type: "string", description: "Scope document: one host/pattern per line (or comma-separated)." },
        target: { type: "string", description: "Host, host:port, or URL to check." },
      },
      required: ["scope", "target"],
    },
    output: {
      schema: { type: "string" },
      render: (_a, v) => [{ type: "text", text: v }],
    },
    async execute(args) {
      const res = scopeAllows(args.scope, args.target);
      return JSON.stringify({ target: normalizeHost(args.target), ...res });
    },
  });

  ctx.tools.register({
    name: "scope_assert",
    description:
      "Batch scope gate. Splits targets into allowed and refused. Call this BEFORE any request loop so an autonomous run physically cannot touch an out-of-scope asset.",
    parameters: {
      type: "object",
      properties: {
        scope: { type: "string", description: "Scope document." },
        targets: { type: "string", description: "Targets to check, one per line (or comma-separated)." },
      },
      required: ["scope", "targets"],
    },
    output: {
      schema: { type: "string" },
      render: (_a, v) => [{ type: "text", text: v }],
    },
    async execute(args) {
      const targets = String(args.targets || "")
        .split(/[\n,]/)
        .map((s) => s.trim())
        .filter(Boolean);
      const allowed = [];
      const refused = [];
      for (const t of targets) {
        const r = scopeAllows(args.scope, t);
        const host = normalizeHost(t);
        if (r.allowed) allowed.push(host);
        else refused.push({ target: host, reason: r.reason });
      }
      return JSON.stringify({
        allowed: [...new Set(allowed)],
        refused,
        safe: refused.length === 0,
        checked: targets.length,
      });
    },
  });

  console.log("[scope-guard] registered: scope_check, scope_assert");
}
