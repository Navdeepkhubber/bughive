import { scopeAllows } from "../dsh-scope-guard/index.js";

export const name = "fp-filter";
export const inject = ["tools", "sessions"];

export function apply(ctx, config = {}) {
  const cfg = { minConfidence: 0.6, ...config };

  ctx.tools.register({
    name: "pre_validation_filter",
    description:
      "Cheap deterministic filter. Rejects out-of-scope hypotheses and candidates without a request target before HTTP traffic is sent.",
    parameters: {
      type: "object",
      properties: {
        hypothesis: { type: "string", description: "Hypothesis as JSON." },
        scope:      { type: "string", description: "In-scope host list, one per line." },
        reconSummary: { type: "string", description: "Phase 04 summary as JSON (optional)." },
      },
      required: ["hypothesis"],
    },
    output: {
      schema: { type: "string" },
      render: (_a, v) => [{ type: "text", text: v }],
    },
    async execute(args) {
      let hyp;
      try { hyp = JSON.parse(args.hypothesis); }
      catch (e) { return JSON.stringify({ pass: false, reason: `bad JSON: ${e.message}` }); }

      const reasons = [];

      // 1. Scope
      if (args.scope) {
        const target = String(hyp.target || hyp.endpoint || "").toLowerCase();
        const scope = scopeAllows(args.scope, target);
        if (!scope.allowed) {
          reasons.push(`target out of scope: ${scope.reason}`);
        }
      }

      // 2. Baseline exists
      const targetUrl = String(hyp.target || hyp.endpoint || "");
      if (!hyp.baseline && !hyp.baselineRequest && !/^https?:\/\//i.test(targetUrl)) {
        reasons.push("no baseline request or target URL supplied");
      }

      return JSON.stringify({ pass: reasons.length === 0, reasons,
        suggested_baseline: !hyp.baseline && !hyp.baselineRequest && /^https?:\/\//i.test(targetUrl)
          ? { method: "GET", url: targetUrl } : null });
    },
  });

  ctx.tools.register({
    name: "llm_falsifier",
    description:
      "Falsifier-first LLM check. Instead of proving the finding real, the model hunts for concrete false-positive signals. Returns {likely_real, confidence, signals}.",
    parameters: {
      type: "object",
      properties: {
        finding: { type: "string", description: "Finding as JSON with request/response evidence." },
      },
      required: ["finding"],
    },
    output: {
      schema: { type: "string" },
      render: (_a, v) => [{ type: "text", text: v }],
    },
    async execute(args) {
      const s = await ctx.sessions.create({ title: `fp-falsifier ${Date.now()}` });
      const prompt =
        `You are a bug-bounty false-positive detector.\n` +
        `Your job is NOT to prove the finding real — it is to hunt for concrete false-positive signals.\n\n` +
        `Signals to check:\n` +
        `- Scheme-mismatch redirect artifacts (http→https)\n` +
        `- WAF/block pages, generic challenge pages\n` +
        `- Wrong-product matches (template thinks Apache, banner says nginx)\n` +
        `- Contradicted matcher DSL (regex expects X, body shows Y)\n` +
        `- Placeholder values (example.com, changeme, TODO)\n` +
        `- Auth-wall false positives (200 login page returned to unauth probe)\n\n` +
        `Finding:\n${args.finding}\n\n` +
        `Emit ONLY JSON: { "signals": [...], "likely_real": bool, "confidence": 0.0-1.0, "reason": "..." }`;

      const r = await s.run(prompt, { maxTokens: 2000 });
      const text = (r.output || "").trim();
      let parsed;
      try { parsed = JSON.parse(text.replace(/^```json\s*|\s*```$/g, "")); }
      catch { parsed = { likely_real: null, confidence: 0, reason: "unparseable" }; }

      const pass = parsed.likely_real === true && parsed.confidence >= cfg.minConfidence;
      return JSON.stringify({ ...parsed, pass });
    },
  });

  console.log("[fp-filter] registered (minConfidence =", cfg.minConfidence, ")");
}
