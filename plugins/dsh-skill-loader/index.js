import { readdir, readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

export const name = "skill-loader";
export const inject = ["tools"];

const HERE = dirname(fileURLToPath(import.meta.url));
const PIPELINE_ROOT = join(HERE, "..", "..");

const SEVERITY_WEIGHT = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };

function parseFrontmatter(src) {
  const m = src.match(/^---\n([\s\S]*?)\n---/);
  if (!m) return {};
  const out = {};
  for (const line of m[1].split("\n")) {
    const kv = line.match(/^([a-z_]+):\s*(.*)$/i);
    if (kv) out[kv[1].trim()] = kv[2].trim();
  }
  return out;
}

export function apply(ctx, config = {}) {
  const cfg = { skillsRoot: join(PIPELINE_ROOT, "skills"), maxSkillsPerHunt: 3, ...config };

  async function listSkills() {
    const out = [];
    for (const sub of ["seeds", "learned"]) {
      let entries;
      try { entries = await readdir(join(cfg.skillsRoot, sub)); }
      catch { continue; }
      for (const f of entries) {
        if (!f.endsWith(".md") || f === "README.md" || f === "_schema.md") continue;
        const path = join(cfg.skillsRoot, sub, f);
        try {
          const body = await readFile(path, "utf-8");
          out.push({ sub, file: f, body, meta: parseFrontmatter(body) });
        } catch {}
      }
    }
    return out;
  }

  ctx.tools.register({
    name: "load_skills_for_target",
    description:
      "Return master skill + at most N vuln-class skills, ranked by keyword overlap and provenance signal (severity × bounty).",
    parameters: {
      type: "object",
      properties: {
        profile: { type: "string", description: "Target description (tech stack, endpoints, auth)." },
      },
      required: ["profile"],
    },
    output: {
      schema: { type: "string" },
      render: (_a, v) => [{ type: "text", text: v }],
    },
    async execute(args) {
      const profile = String(args.profile || "");
      const keywords = [...new Set(profile.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length >= 3))];

      let master = "";
      try { master = await readFile(join(cfg.skillsRoot, "bughunter.md"), "utf-8"); }
      catch { master = "# SKILL: bughunter (master)\n(missing)"; }

      const all = await listSkills();
      const ranked = all.map((s) => {
        const lower = s.body.toLowerCase();
        let kw = 0;
        for (const w of keywords) if (lower.includes(w)) kw += 1;
        const sev = SEVERITY_WEIGHT[String(s.meta.severity || "").toLowerCase()] ?? 0;
        const bounty = Number(s.meta.bounty || 0);
        const provenance = sev * 0.5 + Math.min(bounty / 1000, 3);
        return {
          sub: s.sub,
          file: s.file,
          body: s.body,
          meta: s.meta,
          score: kw + provenance,
        };
      }).sort((a, b) => b.score - a.score);

      const picked = ranked.slice(0, cfg.maxSkillsPerHunt);

      return JSON.stringify({
        master,
        count: picked.length,
        candidates: ranked.length,
        keywords,
        skills: picked.map((p) => ({
          source: `${p.sub}/${p.file}`,
          score: Number(p.score.toFixed(2)),
          provenance: { severity: p.meta.severity, bounty: p.meta.bounty, cwe: p.meta.cwe },
          body: p.body,
        })),
      }, null, 2);
    },
  });

  console.log("[skill-loader] registered; skillsRoot =", cfg.skillsRoot, "(provenance-aware)");
}
