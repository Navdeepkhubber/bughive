export const name = "bounty-budget";
export const inject = [];

export function apply(ctx, config = {}) {
  console.log("===== CTX-PROBE =====");
  for (const k of Object.keys(ctx).sort()) {
    try {
      const v = ctx[k];
      if (v && typeof v === "object") {
        console.log(`  ctx.${k} → [${Object.keys(v).slice(0, 30).sort().join(", ")}]`);
      } else if (typeof v === "function") {
        console.log(`  ctx.${k} → function`);
      }
    } catch {}
  }
  for (const n of ["tools", "sessions", "approval", "llm", "agent", "model", "budget", "events", "config"]) {
    const v = ctx.get ? ctx.get(n) : undefined;
    console.log(`  ctx.get('${n}') → ${v ? "present" : "MISSING"}`);
  }
  console.log("===== END CTX-PROBE =====");

  const cfg = {
    budgets: { session: 2.0, daily: 15.0, monthly: 200.0 },
    tokenLimits: { maxOutputPerCall: 50000, maxTotalPerSession: 500000, maxCacheMissRatio: 0.3 },
    warnRatio: 0.75,
    webhookUrl: null,
    ...config,
  };

  const budget = typeof ctx.get === "function" ? ctx.get("budget") : undefined;
  const toks = new Map();

  async function alert(kind, payload) {
    if (!cfg.webhookUrl) return;
    try {
      await fetch(cfg.webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert: kind, ts: new Date().toISOString(), ...payload }),
      });
    } catch (e) {
      console.error("[bounty-budget] webhook:", e.message);
    }
  }

  ctx.on("model/response", async (e) => {
    const { sessionId, usage } = e;
    if (usage.outputTokens > cfg.tokenLimits.maxOutputPerCall) {
      await alert("call_output_limit", { sessionId, ...usage });
    }
    const next = (toks.get(sessionId) || 0) + (usage.inputTokens || 0) + (usage.outputTokens || 0);
    toks.set(sessionId, next);
    if (next > cfg.tokenLimits.maxTotalPerSession) {
      await alert("session_token_limit", { sessionId, totalTokens: next });
      budget?.blockSession?.(sessionId, "token ceiling");
    }
  });

  console.log("[bounty-budget] registered");
}
