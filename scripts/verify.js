#!/usr/bin/env node
import { existsSync } from "node:fs";
const need=[
  ["AGENTS.md","AGENTS.md"],
  ["intelligence/fetch-h1-reports.py","GraphQL fetcher (no token)"],
  ["intelligence/requirements.txt","python deps"],
  ["intelligence/categories.py","CWE classifier"],
  [".github/workflows/fetch-reports.yml","GH Actions workflow"],
  ["skills/bughunter.md","master skill"],
  ["skills/seeds/xss.md","xss seed"],
  ["recon/phases/01-subdomain-enum.md","recon phase 1"],
  ["agents/parent.md","parent agent"],
  ["plugins/dsh-h1-classifier/index.js","classifier"],
  ["plugins/dsh-bounty-budget/index.js","budget"],
  ["plugins/dsh-critical-gate/index.js","gate"],
  ["plugins/dsh-recon-orchestrator/index.js","recon orch"],
  ["plugins/dsh-skill-loader/index.js","skill loader"],
  ["plugins/dsh-finding-validator/index.js","validator"],
  ["plugins/dsh-chain-builder/index.js","chain builder"],
  ["plugins/dsh-report-writer/index.js","report writer"],
  ["plugins/dsh-observability/index.js","observability"],
  ["playbooks/xss-to-ato.md","playbook xss→ato"],
  ["playbooks/ssrf-to-cloud-metadata.md","playbook ssrf→cloud"],
  ["observability/events.schema.json","events schema"]
];
let ok=true;
for(const [p,l] of need){const e=existsSync(p);console.log(`${e?"✓":"✗"} ${l}`);if(!e)ok=false;}
console.log("✓ No H1 API token required (GraphQL public endpoint)");
process.exit(ok?0:1);
