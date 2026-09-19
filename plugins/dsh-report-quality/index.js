export const name = "report-quality";
export const inject = ["tools"];

const REQUIRED_SECTIONS = ["Title", "Severity", "Summary", "Steps to Reproduce", "Impact", "Remediation", "Evidence"];
const PLACEHOLDERS = /\b(TBD|TODO|FIXME|NEEDS EVIDENCE|example\.com|changeme|<insert)\b/i;

function sectionBody(md, name) {
  const rx = new RegExp(`^#{1,3}\\s+${name}\\s*$([\\s\\S]*?)(?=^#{1,3}\\s|\\Z)`, "mi");
  const m = md.match(rx);
  return m ? m[1].trim() : null;
}

export function apply(ctx, config = {}) {
  const cfg = { maxPlaceholders: 0, ...config };

  ctx.tools.register({
    name: "report_quality_gate",
    description:
      "Pre-send checklist. Verifies every required section is present, no placeholder text remains, severity maps to evidence, and reproduction steps are deterministic. Fail → the report does NOT go to human-gate.",
    parameters: {
      type: "object",
      properties: {
        report: { type: "string", description: "Full report markdown." },
      },
      required: ["report"],
    },
    output: {
      schema: { type: "string" },
      render: (_a, v) => [{ type: "text", text: v }],
    },
    async execute(args) {
      const md = String(args.report || "");
      const failures = [];

      // 1. Every required section present and non-empty
      for (const s of REQUIRED_SECTIONS) {
        const body = sectionBody(md, s);
        if (body === null) failures.push(`section "${s}" missing`);
        else if (body.length < 10) failures.push(`section "${s}" is empty`);
      }

      // 2. Placeholders
      const ph = md.match(PLACEHOLDERS);
      if (ph && ph.length > cfg.maxPlaceholders) {
        failures.push(`placeholder text remains: ${[...new Set(ph)].join(", ")}`);
      }

      // 3. Severity ↔ impact alignment
      const sev = (sectionBody(md, "Severity") || "").toLowerCase();
      const impact = (sectionBody(md, "Impact") || "").toLowerCase();
      if (/critical/.test(sev) && !/(rce|takeover|auth|bypass|full|admin|pii|financial|leak)/.test(impact)) {
        failures.push("severity claims critical but impact does not substantiate it");
      }

      // 4. Steps to reproduce must reference concrete artifacts
      const steps = sectionBody(md, "Steps to Reproduce") || "";
      const hasNumbered = /^\s*\d+[\.\)]\s/m.test(steps);
      const hasArtifact = /`[^`]+`|https?:\/\//.test(steps);
      if (!hasNumbered) failures.push("Steps to Reproduce is not numbered");
      if (!hasArtifact) failures.push("Steps to Reproduce contains no request/URL/code artifact");

      // 5. Evidence
      const evidence = sectionBody(md, "Evidence") || "";
      if (evidence.length < 40) failures.push("Evidence section is thin (< 40 chars)");

      const pass = failures.length === 0;
      return JSON.stringify({ pass, failures });
    },
  });

  console.log("[report-quality] registered");
}
