#!/usr/bin/env node
/**
 * Runs JEV, then any bash executor it named, then JEV again.
 * Stops when the executor needs the LLM (subagent / plugin / write / halt).
 *
 *   node scripts/pipeline/jev-loop.mjs <domain> [--max-steps N]
 */

import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { decide, sanitizeDomain, phaseRunId } from "./jev-decide.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");

function run(command) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, {
      cwd: ROOT,
      env: process.env,
      shell: true,
      stdio: "inherit",
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${command} exited ${code}`));
    });
  });
}

export async function loop(domain, { maxSteps = 32, approveGates = false } = {}) {
  const d = sanitizeDomain(domain);
  const steps = [];
  for (let i = 0; i < maxSteps; i += 1) {
    const decision = await decide(d);
    const ex = decision.executor || {};
    steps.push({
      next_action: decision.next_action,
      recon_phase: decision.recon_phase,
      skill: decision.skill,
      kind: ex.kind,
    });
    if (ex.kind === "bash" && ex.command) {
      await run(ex.command);
      await markStage(d, ex.stage);
      continue;
    }
    // Standing human approval (opt-in): a human_gate whose only blocker was the
    // human_review score still carries JEV's own requested action in
    // resume_command. When the operator has approved the gates for this hunt, resume
    // the planner's action instead of stopping. Never implied -- requires the flag.
    if (approveGates && ex.kind === "halt" && ex.resume_command) {
      steps.push({
        approved_gate: true,
        clamped_from: decision.clamped_from,
        resumed: ex.resume_command,
      });
      await run(ex.resume_command);
      await markStage(d, phaseRunId(decision.recon_phase_selected));
      continue;
    }
    return {
      status: ex.kind === "halt" ? "human_gate" : "needs_llm",
      decision,
      steps,
    };
  }
  return { status: "max_steps", decision: steps.at(-1) || null, steps };
}

// Record each executed stage so `status` and the next snapshot reflect real progress.
async function markStage(domain, stage) {
  if (!stage) return;
  await run(`bash scripts/pipeline/run.sh mark ${domain} ${stage}`);
}

const invokedDirectly =
  process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) {
  const domain = process.argv[2];
  const maxIdx = process.argv.indexOf("--max-steps");
  const maxSteps = maxIdx >= 0 ? Number(process.argv[maxIdx + 1]) || 32 : 32;
  const approveGates = process.argv.includes("--approve-gates");
  if (!domain || domain.startsWith("--")) {
    console.error("usage: jev-loop.mjs <domain> [--max-steps N] [--approve-gates]");
    process.exit(1);
  }
  loop(domain, { maxSteps, approveGates })
    .then((out) => {
      console.log(
        JSON.stringify({
          phase: "loop",
          status: out.status,
          steps: out.steps,
          next_action: out.decision?.next_action,
          executor: out.decision?.executor,
        }),
      );
      process.exit(out.status === "human_gate" ? 0 : 10);
    })
    .catch((err) => {
      console.error(err.message || err);
      process.exit(err.code === "NO_KEY" ? 2 : 1);
    });
}
