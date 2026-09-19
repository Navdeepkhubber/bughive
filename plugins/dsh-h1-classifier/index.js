import { readdir, readFile, writeFile, mkdir, rename } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import { randomUUID } from "node:crypto";

export const name = "h1-classifier";
export const inject = ["agents", "agentDefaultModel", "agentPresets", "tools"];

function expandHome(p) {
  if (typeof p !== "string") return p;
  if (p === "~") return homedir();
  if (p.startsWith("~/")) return join(homedir(), p.slice(2));
  return p;
}

export function apply(ctx, config = {}) {
  const cfg = {
    queueDir: join(homedir(), ".dsh", "bounty-queue"),
    archiveDir: join(homedir(), ".dsh", "bounty-archive"),
    skillsDir: join(homedir(), ".dsh", "skills", "learned"),
    pollIntervalMs: 60000,
    maxTokens: 8000,
    agentPreset: "standard",
    cwd: process.cwd(),
    ...config,
  };
  cfg.queueDir = expandHome(cfg.queueDir);
  cfg.archiveDir = expandHome(cfg.archiveDir);
  cfg.skillsDir = expandHome(cfg.skillsDir);

  function resolveRoute() {
    const sel = ctx.agentDefaultModel?.currentSelection?.();
    if (sel && sel.provider && sel.model) {
      return { provider: sel.provider, model: sel.model, reasoningEffort: sel.reasoningEffort };
    }
    throw new Error("agentDefaultModel.currentSelection() returned empty");
  }

  console.log("[h1-classifier] plugin loaded; queueDir =", cfg.queueDir);

  // Calls another registered tool the same way the real ToolRuntime.execute()
  // contract requires (callId/name/arguments/signal; agent omitted since this
  // is a plugin-internal call, not a model-direct one). See
  // plugins/PLUGIN-FIXES.md for the API this was verified against.
  async function callTool(toolName, args) {
    const controller = new AbortController();
    const result = await ctx.tools.execute({
      callId: randomUUID(),
      name: toolName,
      arguments: args,
      signal: controller.signal,
    });
    if (result.isError) {
      throw new Error(`${toolName} failed: ${JSON.stringify(result.error)}`);
    }
    return result.value;
  }

  let busy = false;

  const buildPrompt = (r) =>
    `Analyze this disclosed HackerOne report and emit ONLY a SKILL.md ` +
    `(under 1000 tokens, no preamble, no fences).\n` +
    `Sections: 1 Trigger Conditions, 2 Root Cause Pattern, 3 Recon Checklist, ` +
    `4 Hunt Methodology, 5 Payload Patterns, 6 WAF Bypass Tips, ` +
    `7 Triage Guidance, 8 Example.\n` +
    `Report: ${JSON.stringify(r)}`;

  async function runOne(report) {
    const route = resolveRoute();
    console.log(`[h1-classifier] route: ${route.provider} / ${route.model}`);

    const sessionId = `h1-classifier-${report.h1Id}-${Date.now()}`;
    const handle = await ctx.agents.create({
      sessionId,
      meta: { cwd: cfg.cwd, agentPreset: cfg.agentPreset },
      agentOptions: {
        provider: route.provider,
        model: route.model,
        maxTokens: cfg.maxTokens,
        ...(route.reasoningEffort ? { reasoningEffort: route.reasoningEffort } : {}),
      },
      setup: async (agentCtx) => {
        await ctx.agentPresets.mount(agentCtx, cfg.agentPreset);
      },
    });

    try {
      await new Promise((r) => setTimeout(r, 500));

      handle.agent.followup({
        content: [{ type: "text", text: buildPrompt(report) }],
        source: { kind: "plugin", plugin: "h1-classifier" },
      });

      await handle.agent.whenIdle();

      const session = handle.agent?.session || handle.session;
      const events =
        typeof session?.snapshotEvents === "function"
          ? session.snapshotEvents()
          : Array.isArray(session?.events)
          ? session.events
          : [];

      for (let i = events.length - 1; i >= 0; i--) {
        const e = events[i];
        if (e?.type === "assistant/message") {
          const content = e.data?.message?.content || e.message?.content || e.data?.content || [];
          const text = content.filter((c) => c.type === "text").map((c) => c.text).join("");
          if (text) return text;
        }
      }

      const types = events.map((e) => e?.type || "?").join(", ");
      const turnEnd = [...events].reverse().find((e) => e?.type === "turn/end");
      console.error("[h1-classifier] turn/end event:", JSON.stringify(turnEnd, null, 2).slice(0, 2000));
      throw new Error(`no assistant/message (${events.length} events: ${types})`);
    } finally {
      try { await handle.dispose(); } catch {}
    }
  }

  async function tick() {
    if (busy) return;
    busy = true;
    try {
      await mkdir(cfg.queueDir, { recursive: true });
      await mkdir(cfg.archiveDir, { recursive: true });
      await mkdir(cfg.skillsDir, { recursive: true });

      const files = (await readdir(cfg.queueDir))
        .filter((f) => f.startsWith("h1-") && f.endsWith(".json"))
        .sort();
      if (files.length === 0) return;
      console.log(`[h1-classifier] tick — ${files.length} file(s) in queue`);

      for (const f of files) {
        const p = join(cfg.queueDir, f);
        try {
          const r = JSON.parse(await readFile(p, "utf-8"));
          console.log(`[h1-classifier] processing ${f}`);
          const text = await runOne(r);
          const slug = (r.cwe && r.cwe.id) || "generic";
          const filename = `h1-${slug}-${r.h1Id}.md`;

          // Write to a staging path OUTSIDE skills/learned/ first. Both gate
          // tools take a `path` and read the library fresh from disk each
          // call; if the candidate were already sitting in skills/learned/
          // when dedupe scans that directory, it would trivially match
          // itself (100% overlap) and every candidate would self-reject.
          const stagingDir = join(cfg.skillsDir, "..", "staging");
          await mkdir(stagingDir, { recursive: true });
          const stagingPath = join(stagingDir, filename);
          await writeFile(stagingPath, `<!-- auto: ${r.reportUrl} -->\n\n${text}`, "utf-8");

          // Route through the admission gate before letting this candidate
          // stay in skills/learned/. This was previously dead code -- the
          // gate existed (dsh-skill-admission), its REQUIRED_SECTIONS match
          // this classifier's own prompt exactly, but nothing ever called
          // it, so every generated skill bypassed the 200-1000 token budget
          // check, section-completeness check, and dedup entirely.
          let rejectReason = null;
          try {
            const dedupe = await callTool("dedupe_skill_candidate", { path: stagingPath, cwe: slug });
            if (dedupe.duplicate) {
              rejectReason = `duplicate of ${dedupe.closest} (overlap ${dedupe.overlap})`;
            } else {
              const admission = await callTool("validate_skill_candidate", {
                path: stagingPath,
                cwe: slug,
                severity: r.severity,
                bounty: r.bountyAmount,
                source: r.reportUrl,
              });
              if (!admission.admitted) {
                rejectReason = `admission failed: ${(admission.failures || []).join("; ")}`;
              }
            }
          } catch (gateErr) {
            // Fail closed: if the gate itself errors, don't let an
            // unvetted candidate reach the live skill library.
            rejectReason = `admission gate error: ${gateErr.message}`;
          }

          if (rejectReason) {
            const rejectedDir = join(cfg.skillsDir, "..", "rejected");
            await mkdir(rejectedDir, { recursive: true });
            await rename(stagingPath, join(rejectedDir, filename));
            console.log(`[h1-classifier] ✗ rejected ${r.h1Id}: ${rejectReason}`);
          } else {
            // validate_skill_candidate already wrote frontmatter onto the
            // staged file in place; promote it into the live library now.
            const dest = join(cfg.skillsDir, filename);
            await rename(stagingPath, dest);
            console.log(`[h1-classifier] ✓ ${r.h1Id} → ${dest} (admitted)`);
          }

          await rename(p, join(cfg.archiveDir, f));
        } catch (e) {
          console.error(`[h1-classifier] ✗ ${f}: ${e.message}`);
        }
      }
    } catch (e) {
      console.error("[h1-classifier] tick error:", e.message);
    } finally {
      busy = false;
    }
  }

  const t = setInterval(tick, cfg.pollIntervalMs);
  tick();

  return () => clearInterval(t);
}
