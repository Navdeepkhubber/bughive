/**
 * dsh-validators — per-class programmatic validators.
 *
 * WHY THIS EXISTS
 * XBOW's stated edge is not detection, it is PRECISION: "we developed the concept of
 * validators, automated peer reviewers that confirm each vulnerability". The pipeline had
 * one generic HTTP-diff check (`validate_finding`), which cannot tell a real blind SQLi
 * from a slow endpoint, or a real open redirect from a same-host bounce.
 *
 * Each validator here encodes the actual proof condition for one bug class:
 *
 *   validate_timing   -- blind SQLi / command injection. Median of N probe samples must
 *                        exceed the median of N baseline samples by about the injected
 *                        delay. Median + repeated sampling defeats jitter.
 *   validate_boolean  -- blind SQLi. TRUE-condition and FALSE-condition responses must
 *                        differ from each other while TRUE matches a known-good baseline.
 *                        Guards against the classic "random page differs anyway" trap.
 *   validate_redirect -- open redirect. An intermediary, NOT the caller, must follow the
 *                        untrusted value off-origin. Client-side-only redirect JS does not
 *                        count, and neither does a redirect back to the same host.
 *   validate_oob      -- blind SSRF/XXE/RCE. Confirms only if the OOB listener recorded
 *                        an interaction for the token (see dsh-oob).
 *
 * Every validator returns {validated, confidence, evidence, note}. `low-likely-noise` is
 * treated as NOT validated, matching the existing pipeline convention.
 */

export const name = "validators";
export const inject = ["tools"];

function median(xs) {
  if (!xs.length) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

/** Strip content that legitimately changes between requests, so diffs mean something. */
export function normalizeBody(text) {
  return String(text || "")
    .replace(/\b\d{4}-\d{2}-\d{2}T[\d:.]+Z?\b/g, "<TS>")
    .replace(/\b[0-9a-f]{16,}\b/gi, "<HEX>")
    .replace(/csrf[_-]?token["'\s:=]+[A-Za-z0-9_-]{8,}/gi, "csrf=<TOKEN>")
    .replace(/\b\d{10,13}\b/g, "<NUM>")
    .trim();
}

export function summarizeSamples(samples) {
  const times = samples.map((s) => s.ms);
  return {
    n: samples.length,
    min: Math.round(Math.min(...times)),
    max: Math.round(Math.max(...times)),
    median: Math.round(median(times)),
  };
}

/** Core timing decision, exported for offline testing. */
export function decideTiming(baseline, probe, injectedMs, tolerance = 0.6) {
  const b = summarizeSamples(baseline);
  const p = summarizeSamples(probe);
  const delta = p.median - b.median;
  const needed = injectedMs * tolerance;
  const confirmed = delta >= needed;
  let confidence = "none";
  if (confirmed) confidence = p.min - b.max >= needed ? "high" : "medium";
  return {
    validated: confirmed,
    confidence,
    evidence: { baseline_ms: b, probe_ms: p, delta_ms: Math.round(delta), required_delta_ms: Math.round(needed) },
    note: confirmed
      ? `Probe median exceeds baseline median by ${Math.round(delta)}ms, consistent with a ${injectedMs}ms injected delay.`
      : `Only ${Math.round(delta)}ms slower; below the ${Math.round(needed)}ms required. Consistent with jitter, not an injection.`,
  };
}

/** Core boolean decision, exported for offline testing. */
export function decideBoolean(baseline, trueResp, falseResp) {
  const b = normalizeBody(baseline.body);
  const t = normalizeBody(trueResp.body);
  const f = normalizeBody(falseResp.body);
  const trueMatchesBaseline = b === t && baseline.status === trueResp.status;
  const conditionsDiffer = t !== f || trueResp.status !== falseResp.status;
  const validated = trueMatchesBaseline && conditionsDiffer;
  return {
    validated,
    confidence: validated ? (b === t ? "high" : "medium") : "none",
    evidence: {
      baseline_status: baseline.status,
      true_status: trueResp.status,
      false_status: falseResp.status,
      true_matches_baseline: trueMatchesBaseline,
      conditions_differ: conditionsDiffer,
      true_len: t.length,
      false_len: f.length,
      baseline_len: b.length,
    },
    note: validated
      ? "TRUE condition matches the baseline and FALSE differs — consistent with boolean-based injection."
      : !trueMatchesBaseline
        ? "TRUE condition does not match the baseline, so the comparison is not controlled. Not validated."
        : "TRUE and FALSE responses are identical; no boolean signal. Not validated.",
  };
}

/** Core redirect decision, exported for offline testing. */
export function decideRedirect(location, allowedHosts, status) {
  if (!location) {
    return { validated: false, confidence: "none", evidence: { status }, note: "No Location header — not a redirect." };
  }
  let host = "";
  let offOrigin = false;
  try {
    const u = new URL(location);
    host = u.host;
    offOrigin = !allowedHosts.some((h) => host === h || host.endsWith(`.${h}`));
  } catch {
    // Protocol-relative (//evil.com) or malformed: treat as off-origin, which is the bug.
    offOrigin = /^\/\//.test(location) || /^[a-z]+:\/\//i.test(location);
    host = location.slice(0, 80);
  }
  const in3xx = status >= 300 && status < 400;
  return {
    validated: offOrigin && in3xx,
    confidence: offOrigin && in3xx ? "high" : "none",
    evidence: { status, location, host, off_origin: offOrigin },
    note:
      offOrigin && in3xx
        ? `Server issued a ${status} redirect to off-origin host ${host}. This is a server-side open redirect.`
        : !in3xx
          ? `Response status ${status} is not a redirect — the value was not honoured server-side.`
          : "Redirect stayed on an allowed host. Not validated.",
  };
}

async function fetchSample(url, opts = {}, timeoutMs = 10000) {
  const started = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...opts, signal: ctrl.signal, redirect: "manual" });
    const body = await res.text().catch(() => "");
    return { ms: Date.now() - started, status: res.status, body, headers: Object.fromEntries(res.headers) };
  } catch (e) {
    return { ms: Date.now() - started, status: 0, body: "", error: String(e.message || e), headers: {} };
  } finally {
    clearTimeout(timer);
  }
}

/** Class-router helpers: fetch, then decide, reusing the pure decision functions above. */
async function urlFetch(url, method, headers) {
  return fetchSample(url, { method: method || "GET", headers: headers || {} });
}

function headersOf(spec) {
  return typeof spec.headers === "object" && spec.headers ? spec.headers : {};
}

async function decideTimingCall(spec) {
  const n = Number.isFinite(spec.samples) ? Math.max(2, Math.min(6, spec.samples)) : 3;
  const method = (spec.method || "GET").toUpperCase();
  const headers = headersOf(spec);
  const baseline = [];
  const probe = [];
  for (let i = 0; i < n; i += 1) baseline.push(await urlFetch(spec.baselineUrl, method, headers));
  for (let i = 0; i < n; i += 1) probe.push(await urlFetch(spec.probeUrl, method, headers));
  return decideTiming(baseline, probe, Number(spec.injectedMs));
}

async function booleanCall(spec) {
  const method = (spec.method || "GET").toUpperCase();
  const headers = headersOf(spec);
  const [b, t, f] = await Promise.all([
    urlFetch(spec.baselineUrl, method, headers),
    urlFetch(spec.trueUrl, method, headers),
    urlFetch(spec.falseUrl, method, headers),
  ]);
  return decideBoolean(b, t, f);
}

async function redirectCall(spec) {
  const res = await urlFetch(spec.url, (spec.method || "GET").toUpperCase(), headersOf(spec));
  const allowed = (Array.isArray(spec.allowedHosts) ? spec.allowedHosts : String(spec.allowedHosts).split(","))
    .map((s) => String(s).trim())
    .filter(Boolean);
  return {
    ...decideRedirect(res.headers.location || "", allowed, res.status),
    request_status: res.status,
  };
}

function oobDecision(token, interactions) {
  let items = interactions;
  if (typeof items === "string") {
    try {
      items = JSON.parse(items);
    } catch {
      items = [];
    }
  }
  const hits = (Array.isArray(items) ? items : []).filter((i) => i && i.token === token);
  return {
    validated: hits.length > 0,
    confidence: hits.length > 0 ? "high" : "none",
    evidence: { interaction_count: hits.length, kinds: [...new Set(hits.map((h) => h.kind))] },
    note:
      hits.length > 0
        ? "Out-of-band interaction received for this token."
        : "No interaction recorded for this token. Not validated.",
  };
}

export function apply(ctx) {
  ctx.tools.register({
    name: "validate_timing",
    description:
      "Confirm a time-based blind vulnerability. Sends N baseline and N probe requests, compares medians, and requires the probe median to exceed the baseline by most of the injected delay. Use for blind SQLi (SLEEP/WAITFOR/pg_sleep) and blind command injection. Returns validated=false for ordinary jitter.",
    parameters: {
      type: "object",
      properties: {
        baselineUrl: { type: "string" },
        probeUrl: { type: "string", description: "Same request with the delay payload." },
        injectedMs: { type: "number", description: "Delay the payload should cause (e.g. 5000)." },
        samples: { type: "number", description: "Samples per side (default 3)." },
        method: { type: "string" },
        headers: { type: "string", description: "JSON object of extra headers." },
      },
      required: ["baselineUrl", "probeUrl", "injectedMs"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const n = Number.isFinite(args.samples) ? Math.max(2, Math.min(6, args.samples)) : 3;
      const method = (args.method || "GET").toUpperCase();
      let headers = {};
      if (args.headers) {
        try {
          headers = JSON.parse(args.headers);
        } catch {
          return JSON.stringify({ validated: false, error: "headers must be JSON" });
        }
      }
      const baseline = [];
      const probe = [];
      for (let i = 0; i < n; i += 1) baseline.push(await fetchSample(args.baselineUrl, { method, headers }));
      for (let i = 0; i < n; i += 1) probe.push(await fetchSample(args.probeUrl, { method, headers }));
      return JSON.stringify({ ...decideTiming(baseline, probe, Number(args.injectedMs)), samples_per_side: n });
    },
  });

  ctx.tools.register({
    name: "validate_boolean",
    description:
      "Confirm a boolean-based blind vulnerability. Requires the TRUE-condition response to match a known-good baseline AND the FALSE-condition response to differ. This rejects the common false positive where a page simply differs on every request.",
    parameters: {
      type: "object",
      properties: {
        baselineUrl: { type: "string", description: "Known-good request (no injection)." },
        trueUrl: { type: "string", description: "Payload with a TRUE condition." },
        falseUrl: { type: "string", description: "Payload with a FALSE condition." },
        method: { type: "string" },
        headers: { type: "string" },
      },
      required: ["baselineUrl", "trueUrl", "falseUrl"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const method = (args.method || "GET").toUpperCase();
      let headers = {};
      if (args.headers) {
        try {
          headers = JSON.parse(args.headers);
        } catch {
          return JSON.stringify({ validated: false, error: "headers must be JSON" });
        }
      }
      const [b, t, f] = await Promise.all([
        fetchSample(args.baselineUrl, { method, headers }),
        fetchSample(args.trueUrl, { method, headers }),
        fetchSample(args.falseUrl, { method, headers }),
      ]);
      return JSON.stringify(decideBoolean(b, t, f));
    },
  });

  ctx.tools.register({
    name: "validate_redirect",
    description:
      "Confirm a server-side open redirect. The server itself must answer with a 3xx to an off-origin host; a client-side JS redirect or a bounce back to the same host does not count. Only reportable when chained to ATO/OAuth token theft.",
    parameters: {
      type: "object",
      properties: {
        url: { type: "string", description: "Request containing the untrusted redirect value." },
        allowedHosts: { type: "string", description: "Comma-separated hosts that are legitimate (e.g. target.com)." },
        method: { type: "string" },
        headers: { type: "string" },
      },
      required: ["url", "allowedHosts"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const method = (args.method || "GET").toUpperCase();
      let headers = {};
      if (args.headers) {
        try {
          headers = JSON.parse(args.headers);
        } catch {
          return JSON.stringify({ validated: false, error: "headers must be JSON" });
        }
      }
      const allowed = String(args.allowedHosts).split(",").map((s) => s.trim()).filter(Boolean);
      const res = await fetchSample(args.url, { method, headers });
      const loc = res.headers.location || "";
      return JSON.stringify({ ...decideRedirect(loc, allowed, res.status), request_status: res.status });
    },
  });

  ctx.tools.register({
    name: "validate_oob",
    description:
      "Confirm an out-of-band vulnerability from an OOB interaction record. Pass the interactions returned by oob_wait/oob_poll: a recorded callback for the token IS the proof (blind SSRF, blind XXE, blind XSS, JNDI/RCE).",
    parameters: {
      type: "object",
      properties: {
        token: { type: "string" },
        interactions: { type: "string", description: "JSON array from oob_wait/oob_poll." },
      },
      required: ["token", "interactions"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      let items;
      try {
        items = JSON.parse(args.interactions);
      } catch (e) {
        return JSON.stringify({ validated: false, error: `interactions must be JSON: ${e.message}` });
      }
      const hits = (Array.isArray(items) ? items : []).filter((i) => i && i.token === args.token);
      const kinds = [...new Set(hits.map((h) => h.kind))];
      const srcs = [...new Set(hits.map((h) => h.source_ip).filter(Boolean))];
      return JSON.stringify({
        validated: hits.length > 0,
        confidence: hits.length > 0 ? "high" : "none",
        evidence: { interaction_count: hits.length, kinds, source_ips: srcs, first: hits[0] || null },
        note:
          hits.length > 0
            ? `Out-of-band ${kinds.join("+")} interaction received${srcs.length ? ` from ${srcs.join(", ")}` : ""}. The target processed the payload.`
            : "No interaction recorded for this token. Not validated — do not report.",
      });
    },
  });

  ctx.tools.register({
    name: "validate_by_class",
    description:
      "Route a finding to the correct proof condition for its bug class and run it. Encodes the class->validator mapping so the prove stage does not guess: timing/boolean for injection, redirect for open redirect, OOB for blind classes, the headless browser for XSS, and an explicit 'unverifiable' for IDOR/CSRF/takeover (which need two identities or a cross-site PoC, not a payload).",
    parameters: {
      type: "object",
      properties: {
        bugClass: {
          type: "string",
          description: "Canonical or free-text class, e.g. sqli, xss, open-redirect, ssrf, idor.",
        },
        spec: {
          type: "string",
          description:
            "JSON with the class-appropriate fields: {baselineUrl, probeUrl, injectedMs} timing; {baselineUrl,trueUrl,falseUrl} boolean; {url,allowedHosts} redirect; {token,interactions} oob; {url,marker,settleMs} xss.",
        },
      },
      required: ["bugClass", "spec"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      let spec = {};
      if (args.spec) {
        try {
          spec = JSON.parse(args.spec);
        } catch (e) {
          return JSON.stringify({ validated: false, error: `spec must be JSON: ${e.message}` });
        }
      }
      const c = String(args.bugClass || "").toLowerCase().replace(/[\s_]+/g, "-");

      // Classes this plugin can prove itself.
      if (/^(sqli|sql-injection|blind-sqli|time-based|cmdi|command-injection|rce)$/.test(c)) {
        if (spec.baselineUrl && spec.probeUrl && Number.isFinite(spec.injectedMs)) {
          const res = await decideTimingCall(spec);
          return JSON.stringify({ route: "validate_timing", class: c, ...res });
        }
        if (spec.baselineUrl && spec.trueUrl && spec.falseUrl) {
          const res = await booleanCall(spec);
          return JSON.stringify({ route: "validate_boolean", class: c, ...res });
        }
        return JSON.stringify({
          validated: false,
          class: c,
          error: "need {baselineUrl,probeUrl,injectedMs} or {baselineUrl,trueUrl,falseUrl}",
        });
      }
      if (/^(open-redirect|unvalidated-redirect)$/.test(c)) {
        if (!spec.url || !spec.allowedHosts) {
          return JSON.stringify({ validated: false, class: c, error: "need {url,allowedHosts}" });
        }
        const res = await redirectCall(spec);
        return JSON.stringify({ route: "validate_redirect", class: c, ...res });
      }
      if (/^(ssrf|xxe|blind-xss|log4shell|jndi|blind-rce)$/.test(c)) {
        if (!spec.token || spec.interactions === undefined) {
          return JSON.stringify({ validated: false, class: c, error: "need {token,interactions} from oob_wait/oob_poll" });
        }
        return JSON.stringify({ route: "validate_oob", class: c, ...oobDecision(spec.token, spec.interactions) });
      }
      if (/^(xss|reflected-xss|stored-xss|dom-xss)$/.test(c)) {
        if (!spec.url) {
          return JSON.stringify({ validated: false, class: c, error: "need {url} containing the payload" });
        }
        // Delegate to the browser plugin: only real execution proves XSS.
        try {
          const mod = await import("../dsh-browser-validate/index.js");
          const reg = new Map();
          mod.apply({ tools: { register: (d) => reg.set(d.name, d) } });
          const tool = reg.get("validate_xss_browser");
          if (!tool) throw new Error("browser validator not registered");
          const out = JSON.parse(await tool.execute(spec));
          return JSON.stringify({ route: "validate_xss_browser", class: c, ...out });
        } catch (e) {
          return JSON.stringify({
            validated: false,
            class: c,
            error: `browser delegation failed: ${e.message}`,
            note: "XSS cannot be confirmed without the browser validator.",
          });
        }
      }

      // Classes that a payload string cannot prove. Saying so is the honest answer.
      if (/^(idor|csrf|account-takeover|subdomain-takeover|business-logic)$/.test(c)) {
        const why = {
          idor: "requires two identities and a differential read/write",
          csrf: "requires a cross-site PoC in a real browser session",
          "account-takeover": "requires a full end-to-end chain, not a single request",
          "subdomain-takeover": "requires actually serving content from the claimed host",
          "business-logic": "requires a state sequence, not a payload",
        }[c];
        return JSON.stringify({
          validated: false,
          class: c,
          route: "manual",
          reason: `${c} is not provable by payload string: ${why}.`,
          note: "Use coverage_mark with identities>=2 (for IDOR/ATO) or mark it blocked with a reason. Do not report from a payload diff alone.",
        });
      }

      return JSON.stringify({
        validated: false,
        class: c,
        error: `no validator mapped for class "${args.bugClass}"`,
        known: ["sqli", "blind-sqli", "cmdi", "open-redirect", "ssrf", "xxe", "blind-xss", "xss", "idor", "csrf"],
      });
    },
  });

  console.log(
    "[validators] registered: validate_timing, validate_boolean, validate_redirect, validate_oob, validate_by_class"
  );
}
