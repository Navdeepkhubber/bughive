import { readFile, readdir, writeFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export const name = "skill-admission";
export const inject = ["tools"];

const HERE = dirname(fileURLToPath(import.meta.url));
const PIPELINE_ROOT = join(HERE, "..", "..");

const REQUIRED_SECTIONS = [
  "Trigger Conditions",
  "Root Cause Pattern",
  "Recon Checklist",
  "Hunt Methodology",
  "Payload Patterns",
  "WAF Bypass Tips",
  "Triage Guidance",
  "Example",
];

const TARGET_SPECIFIC = [
  /https?:\/\/(?!hackerone\.com\/reports)/i, // URLs other than H1 report links
  /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/,  // IPs
  /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/i, // emails
];

function extractExampleSection(src) {
  const m = src.split(/^##\s+Example\s*$/mi);
  return m.length > 1 ? m.slice(1).join("## Example") : "";
}

function stripExample(src) {
  return src.replace(/^##\s+Example\s*$[\s\S]*$/mi, "");
}

function countTokensApprox(src) {
  return Math.ceil(src.length / 4);
}

export function apply(ctx, config = {}) {
  const cfg = { skillsRoot: join(PIPELINE_ROOT, "skills"), ...config };

  async function loadAllSkills() {
    const out = [];
    for (const sub of ["seeds", "learned"]) {
      let entries;
      try {
        entries = await readdir(join(cfg.skillsRoot, sub));
      } catch {
        continue;
      }
      for (const f of entries) {
        if (!f.endsWith(".md")) continue;
        try {
          const body = await readFile(join(cfg.skillsRoot, sub, f), "utf-8");
          out.push({ sub, file: f, body });
        } catch {}
      }
    }
    return out;
  }

  ctx.tools.register({
    name: "validate_skill_candidate",
    description:
      "Admission gate for a generated SKILL.md. Checks section coverage, token budget, and target-specific leakage. Writes YAML frontmatter on pass.",
    parameters: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute path to the SKILL.md candidate." },
        cwe:  { type: "string", description: "CWE id from the source report." },
        severity: { type: "string", description: "critical | high | medium | low." },
        bounty: { type: "number", description: "Bounty amount in USD (0 if none)." },
        source: { type: "string", description: "Source report URL." },
      },
      required: ["path"],
    },
    output: {
      schema: { type: "string" },
      render: (_a, v) => [{ type: "text", text: v }],
    },
    async execute(args) {
      let src;
      try { src = await readFile(args.path, "utf-8"); }
      catch (e) { return JSON.stringify({ admitted: false, reason: `read failed: ${e.message}` }); }

      const failures = [];

      // 1. Section coverage
      const missing = REQUIRED_SECTIONS.filter((s) => !new RegExp(`^##\\s+${s}\\s*$`, "mi").test(src));
      if (missing.length) failures.push(`missing sections: ${missing.join(", ")}`);

      // 2. Token budget
      const tokens = countTokensApprox(src);
      if (tokens > 1000) failures.push(`token count ${tokens} exceeds 1000`);
      if (tokens < 200)  failures.push(`token count ${tokens} below 200 (too thin)`);

      // 3. Target-specific leakage outside Example
      const nonExample = stripExample(src);
      for (const rx of TARGET_SPECIFIC) {
        const hit = nonExample.match(rx);
        if (hit) failures.push(`target-specific data outside Example: ${hit[0].slice(0, 60)}`);
      }

      if (failures.length) {
        return JSON.stringify({ admitted: false, failures, tokens });
      }

      // 4. Write provenance frontmatter
      const frontmatter =
        `---\n` +
        `cwe: ${args.cwe || "unknown"}\n` +
        `severity: ${args.severity || "unknown"}\n` +
        `bounty: ${args.bounty ?? 0}\n` +
        `source: ${args.source || "unknown"}\n` +
        `admitted: ${new Date().toISOString()}\n` +
        `tokens: ${tokens}\n` +
        `---\n\n`;
      const withFront = src.startsWith("---") ? src : frontmatter + src;
      await writeFile(args.path, withFront, "utf-8");

      return JSON.stringify({ admitted: true, tokens, path: args.path });
    },
  });

  ctx.tools.register({
    name: "dedupe_skill_candidate",
    description:
      "Checks overlap between a candidate SKILL.md and the existing library. Returns {duplicate, overlap, closest}.",
    parameters: {
      type: "object",
      properties: {
        path: { type: "string" },
        cwe:  { type: "string" },
      },
      required: ["path"],
    },
    output: {
      schema: { type: "string" },
      render: (_a, v) => [{ type: "text", text: v }],
    },
    async execute(args) {
      let candidate;
      try { candidate = await readFile(args.path, "utf-8"); }
      catch (e) { return JSON.stringify({ error: e.message }); }

      const all = await loadAllSkills();
      const cand = candidate.toLowerCase();

      const scored = all
        .filter((s) => s.file !== "bughunter.md" && s.file !== "README.md" && s.file !== "_schema.md")
        .map((s) => {
          const body = s.body.toLowerCase();
          const candWords = new Set(cand.split(/[^a-z0-9]+/).filter((w) => w.length >= 4));
          const existWords = new Set(body.split(/[^a-z0-9]+/).filter((w) => w.length >= 4));
          let inter = 0;
          for (const w of candWords) if (existWords.has(w)) inter++;
          const union = candWords.size + existWords.size - inter;
          return { sub: s.sub, file: s.file, overlap: union ? inter / union : 0 };
        })
        .sort((a, b) => b.overlap - a.overlap);

      const top = scored[0];
      return JSON.stringify({
        duplicate: top && top.overlap > 0.6,
        overlap: top ? Number(top.overlap.toFixed(3)) : 0,
        closest: top ? `${top.sub}/${top.file}` : null,
        candidates_checked: scored.length,
      });
    },
  });

  console.log("[skill-admission] registered (admission + dedupe)");
}
