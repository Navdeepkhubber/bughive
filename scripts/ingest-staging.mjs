#!/usr/bin/env node
/**
 * Promote skills/staging into skills/learned and, when a class has no seed, skills/seeds.
 *
 * Permissive licenses (MIT, Apache, BSD, ISC, 0BSD, Unlicense) are copied with
 * provenance. Anything else becomes an original house-style learned skill.
 * Files with no single class are flagged in skills/ingest-report.json and are
 * not loaded. Idempotent: a second run rewrites nothing when inputs are unchanged.
 *
 *   node scripts/ingest-staging.mjs [--dry-run] [--staging DIR] [--learned DIR] [--seeds DIR] [--report FILE]
 */
import { readdir, readFile, writeFile, mkdir, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PERMISSIVE = new Set(["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "0BSD", "Unlicense"]);
const KNOWN_LICENSE = { "Aetherdz/huntpack": "MIT" };
const FAMILY = { sqli: ["sqli", "blind-sqli"], idor: ["idor", "idor-write"] };
const SEED_ALIAS = {
  "missing-auth": "unauth-api",
  "path-traversal": "lfi",
  csrf: "csrf-token-bypass",
};

const RULES = [
  ["cache-poisoning", /cache-poison/],
  ["race-condition", /race-condition/],
  ["request-smuggling", /smuggling/],
  ["subdomain-takeover", /subdomain/],
  ["path-traversal", /path-traversal|directory-traversal|[^a-z]lfi[^a-z]/],
  ["open-redirect", /open-redirect/],
  ["mass-assignment", /mass-assignment/],
  ["host-header-injection", /host-header/],
  ["missing-auth", /auth-bypass|missing-auth/],
  ["file-upload", /file-upload/],
  ["business-logic", /business-logic/],
  ["account-takeover", /[^a-z]ato[^a-z]|account-takeover/],
  ["graphql", /graphql/],
  ["sqli", /sqli|sql-injection/],
  ["xss", /[^a-z]xss[^a-z]/],
  ["idor", /idor/],
  ["ssrf", /ssrf/],
  ["ssti", /ssti/],
  ["xxe", /xxe/],
  ["jwt", /jwt/],
  ["nosql", /nosql/],
  ["cors", /cors/],
  ["oauth", /oauth/],
  ["csrf", /csrf/],
  ["saml", /saml/],
  ["rce", /[^a-z]rce[^a-z]/],
];

const HOUSE = {
  sqli: ["Query and body fields that change which stored rows come back.", "The value is concatenated into a query instead of being bound.", "Compare one true tautology with one false tautology and keep both responses."],
  xss: ["A parameter reflected into HTML.", "The reflection is not escaped for the surrounding context.", "A saved response must contain the unescaped marker. A reflected string alone is not a finding."],
  idor: ["An object id the caller did not create.", "The handler loads the object and skips an authorization check.", "Read two ids. Confirm only when both responses are saved and belong to different owners."],
  ssrf: ["A URL the server fetches.", "The server requests that URL.", "Confirm with an out-of-band hit on an address you control. A body flag alone is not proof."],
  ssti: ["A template name or fragment taken from the caller.", "The server evaluates it.", "Confirm only when the rendered output shows the evaluation and the request was saved."],
  xxe: ["An XML body the server parses.", "External entities are resolved.", "On a local fixture, confirm with the planted marker. Do not request system files on a remote host."],
  graphql: ["A GraphQL endpoint.", "Introspection or a mutation is exposed without an auth check.", "Save the request that returned the schema or executed the mutation."],
  "race-condition": ["A one-time action.", "The check and the update are not atomic.", "Confirm only when more than one parallel response shows the action applied."],
  "cache-poisoning": ["A response that is cached.", "A request header changes the body and is left out of the cache key.", "Save the poisoned response and the baseline."],
  "missing-auth": ["An admin or account route.", "The handler does not require a session.", "Confirm only when the saved response contains the protected data."],
  "open-redirect": ["A next or return parameter.", "The Location header is taken from the caller.", "Save the 3xx response whose Location leaves the site."],
  "path-traversal": ["A filename parameter.", "The path is not confined to the intended directory.", "Confirm with a marker from the fixture, not with a guess."],
  jwt: ["A bearer token the server trusts.", "The signature algorithm is not pinned.", "Confirm only when an unsigned token is accepted and the response was saved."],
  nosql: ["A query parameter parsed as a document.", "Operator keys reach the matcher.", "Save the baseline and the operator response."],
  cors: ["An API read by a browser.", "The server reflects Origin and allows credentials.", "Save the response headers."],
  "host-header-injection": ["A password-reset link.", "The link host is taken from the Host header.", "Save the message that contains the attacker host."],
  "mass-assignment": ["A profile update.", "A privileged field is copied from the body.", "Save the before and after."],
  oauth: ["An OAuth redirect or token endpoint.", "The redirect or state check is missing.", "Save the response that shows the check was skipped."],
  csrf: ["A state-changing request a browser will send.", "No token is checked.", "Save the request that changed state without a token."],
  "request-smuggling": ["A front-end and back-end that disagree on request length.", "The boundary is parsed twice.", "Confirm only with a saved desync, inside scope."],
  "subdomain-takeover": ["A dangling DNS name.", "The target service is unclaimed.", "Confirm only when you control the dangling name and the response was saved."],
  "file-upload": ["An upload that is stored and served.", "The type or path is not constrained.", "Confirm with a benign marker file, inside scope."],
  "business-logic": ["A multi-step flow.", "A step can be skipped or repeated.", "Save both the skipped step and the resulting state."],
  "account-takeover": ["An account recovery or session route.", "A token or code is bound to the wrong account.", "Save the response that shows the other account."],
  saml: ["A SAML response the server accepts.", "The signature or audience is not checked.", "Save the response that was accepted."],
  rce: ["A parameter that reaches a command or template.", "The process runs caller input.", "Confirm with a benign marker you control, on an in-scope host, and save the response."],
};

function arg(name, fallback) {
  const index = process.argv.indexOf(name);
  return index === -1 ? fallback : process.argv[index + 1];
}

function classesOf(haystack) {
  const found = [];
  for (const [name, pattern] of RULES) {
    if (pattern.test(haystack)) found.push(name);
  }
  return found;
}

export function classify(filename, text) {
  const fromFile = classesOf(filename.toLowerCase());
  const nameLine = (text.match(/^name:\s*([^\n]+)/m) || [])[1] || "";
  const fromName = fromFile.length ? [] : classesOf(nameLine.toLowerCase());
  const found = fromFile.length ? fromFile : fromName;
  if (found.length > 1) return { flag: "ambiguous-class", classes: found };
  if (found.length === 0) return { flag: "no-class", classes: [] };
  const primary = found[0];
  return { flag: null, classes: FAMILY[primary] || [primary], primary };
}

export function parseProvenance(filename, text) {
  const harvested = text.match(/harvested:\s*([^/\s]+)\/([^/\s]+)\/(\S+)\s+on\s+(\S+)/);
  const licenseLine = text.match(/license:\s*([^;]+);\s*author:\s*([^;]+);\s*commit:\s*([^;]+);/);
  const repo = harvested ? `${harvested[1]}/${harvested[2]}` : "unknown/unknown";
  const license = (licenseLine ? licenseLine[1].trim() : "") || KNOWN_LICENSE[repo] || "none";
  return {
    source_repo: repo,
    source_path: harvested ? harvested[3] : filename,
    fetched: harvested ? harvested[4] : "unknown",
    source_author: licenseLine ? licenseLine[2].trim() : "unknown",
    source_commit: licenseLine ? licenseLine[3].trim() : "unknown",
    source_license: license,
  };
}

function sourceBody(text) {
  if (!text.startsWith("<!-- harvested:")) return text;
  const split = text.indexOf("\n\n");
  return split === -1 ? "" : text.slice(split + 2);
}

function houseBody(primary) {
  const lines = HOUSE[primary] || [
    "An in-scope input related to this class.",
    "The server trusts that input.",
    "Confirm only with a saved request and response.",
  ];
  return [
    `# SKILL: ${primary}`,
    "## Trigger Conditions",
    lines[0],
    "## Root Cause Pattern",
    lines[1],
    "## Recon Checklist",
    "- [ ] In-scope endpoint that matches this class",
    "## Hunt Methodology",
    lines[2],
    "## Payload Patterns",
    "Use the pinned bughive rule for this class. Do not add a payload that the rule does not already send.",
    "## WAF Bypass Tips",
    "Stay inside scope. A bypass is not a finding until the baseline and the probe are both saved.",
    "## Triage Guidance",
    "Unverified output stays unverified. Confirmed means a saved exchange or a verified API result.",
    "## Example",
    "The local fixture returns a different saved response for the probe than for the baseline.",
  ].join("\n");
}

function learnedDoc(row, body) {
  const meta = {
    id: row.id,
    class: row.primary,
    classes: row.classes,
    mode: row.mode,
    source_repo: row.source_repo,
    source_path: row.source_path,
    source_author: row.source_author,
    source_license: row.source_license,
    source_commit: row.source_commit,
    fetched: row.fetched,
    staged: row.staged,
  };
  const parts = [houseBody(row.primary), "", `<!-- provenance: ${JSON.stringify(meta)} -->`, "", "## Provenance", "```json", JSON.stringify(meta, null, 2), "```"];
  if (row.mode === "permissive-copy") {
    parts.push("", "## Source text", `License ${row.source_license}. Copyright remains with ${row.source_author} (${row.source_repo}).`, "", body);
  }
  return `${parts.join("\n")}\n`;
}

function seedDoc(primary) {
  return `${houseBody(primary)}\n\n## Provenance\nOriginal house-style seed for \`${primary}\`. Per-source attribution is on the matching \`skills/learned/staged-*\` files.\n`;
}

export async function ingestStaging(opts = {}) {
  const staging = opts.staging || join(ROOT, "skills", "staging");
  const learned = opts.learned || join(ROOT, "skills", "learned");
  const seeds = opts.seeds || join(ROOT, "skills", "seeds");
  const reportPath = opts.report || join(ROOT, "skills", "ingest-report.json");
  const names = (await readdir(staging)).filter((name) => name.endsWith(".staged.md")).sort();
  const files = [];
  const written = new Map();
  const seedWrites = [];

  for (const name of names) {
    const text = await readFile(join(staging, name), "utf8");
    const provenance = parseProvenance(name, text);
    const judged = classify(name, text);
    if (judged.flag) {
      files.push({ staged: name, status: "flagged", reason: judged.flag, classes: judged.classes, ...provenance });
      continue;
    }
    const permissive = PERMISSIVE.has(provenance.source_license);
    const idName = `staged-${name.replace(/\.staged\.md$/, "")}`;
    const row = {
      staged: name,
      status: "ingested",
      id: `learned/${idName}`,
      file: `${idName}.md`,
      mode: permissive ? "permissive-copy" : "derived",
      primary: judged.primary,
      classes: judged.classes,
      ...provenance,
    };
    files.push(row);
    written.set(row.file, learnedDoc(row, permissive ? sourceBody(text) : ""));
    const seedName = `${SEED_ALIAS[judged.primary] || judged.primary}.md`;
    if (!seedWrites.some((item) => item.file === seedName)) seedWrites.push({ file: seedName, primary: judged.primary });
  }

  const report = {
    ingested: files.filter((item) => item.status === "ingested").length,
    flagged: files.filter((item) => item.status === "flagged").length,
    seeds_created: [],
    files,
  };

  const ownedSeeds = [];
  for (const seed of seedWrites) {
    const dest = join(seeds, seed.file);
    const body = seedDoc(seed.primary);
    const existing = existsSync(dest) ? await readFile(dest, "utf8") : "";
    if (existing === body || existing === "") ownedSeeds.push(seed.file);
  }
  ownedSeeds.sort();
  report.seeds_created = ownedSeeds;

  if (opts.dryRun) return report;

  await mkdir(learned, { recursive: true });
  await mkdir(seeds, { recursive: true });
  for (const [file, body] of written) {
    const dest = join(learned, file);
    const current = existsSync(dest) ? await readFile(dest, "utf8") : "";
    if (current !== body) await writeFile(dest, body);
  }
  const keep = new Set(written.keys());
  for (const name of await readdir(learned)) {
    if (name.startsWith("staged-") && name.endsWith(".md") && !keep.has(name)) await rm(join(learned, name));
  }
  for (const seed of seedWrites) {
    const dest = join(seeds, seed.file);
    if (existsSync(dest)) continue;
    await writeFile(dest, seedDoc(seed.primary));
  }
  await mkdir(dirname(reportPath), { recursive: true });
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`);
  return report;
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const report = await ingestStaging({
    dryRun: process.argv.includes("--dry-run"),
    staging: arg("--staging", join(ROOT, "skills", "staging")),
    learned: arg("--learned", join(ROOT, "skills", "learned")),
    seeds: arg("--seeds", join(ROOT, "skills", "seeds")),
    report: arg("--report", join(ROOT, "skills", "ingest-report.json")),
  });
  process.stdout.write(`${JSON.stringify({ ingested: report.ingested, flagged: report.flagged, seeds_created: report.seeds_created, dry_run: process.argv.includes("--dry-run") })}\n`);
}
