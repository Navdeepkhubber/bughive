/**
 * Pre-merge check for skills/cloudflare-zero-wire.
 *
 * Frontmatter uses the same rules as parseFrontmatter in
 * plugins/dsh-skill-loader/index.js. The license guard uses the exact
 * attribution_line and reproduction_line strings from
 * scripts/harvest-zero-wire.py. The length cap for each skill is the
 * length of render_skill for that index item: title, link, CVE ids, tags,
 * and pubDate only. A longer file is text the harvester does not write.
 * No network.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, readdir, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { isReproState } from "../plugins/dsh-repro-steps/parse.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const TREE = join(ROOT, "skills", "cloudflare-zero-wire");
const RADAR_HOST = "radar.cloudflare.com";

// Exact strings from scripts/harvest-zero-wire.py. The dash is U+2014.
const REPRO_PREFIX = "Reproduction: not verified \u2014 from Cloudflare Radar Zero Wire brief ";
const TEARDOWN_NOTE = "Verified reproduction requires a teardown.";
const ATTRIBUTION = "Source: Cloudflare Radar Zero Wire, CC BY-NC 4.0";

export function reproductionLine(link) {
  return `${REPRO_PREFIX}${link}.`;
}

export function attributionLine(link) {
  return `${ATTRIBUTION} ${link}`;
}

function parseFrontmatter(src) {
  const matched = src.match(/^---\n([\s\S]*?)\n---/);
  if (!matched) return {};
  const out = {};
  for (const line of matched[1].split("\n")) {
    const kv = line.match(/^([a-z_]+):\s*(.*)$/i);
    if (kv) out[kv[1].trim()] = kv[2].trim();
  }
  return out;
}

function tagLabel(tag) {
  if (tag && tag.domain) return `${tag.term} (${tag.domain})`;
  return tag.term;
}

function summarySentences(item) {
  const cves = Array.isArray(item.cves) ? item.cves : [];
  const tags = Array.isArray(item.tags) ? item.tags : [];
  const cveBit = cves.length > 0
    ? ` covering ${cves.join(", ")}`
    : " with no CVE id in the feed categories";
  const tagTerms = tags.map((tag) => tag.term).filter(Boolean).join(", ") || "none";
  const published = item.pubDate || "an unknown date";
  const first = `${item.title} is a Cloudflare Radar Zero Wire briefing${cveBit}, published ${published}.`;
  const second = `Tags: ${tagTerms}.`;
  return [first, second];
}

/** Same template as harvest-zero-wire.py render_skill. */
export function renderSkill(item) {
  const [first, second] = summarySentences(item);
  const cves = Array.isArray(item.cves) && item.cves.length > 0 ? item.cves.join(", ") : "none";
  const tags = Array.isArray(item.tags) && item.tags.length > 0
    ? item.tags.map(tagLabel).join(", ")
    : "none";
  const published = item.pubDate || "unknown";
  return [
    "---",
    `name: ${item.name}`,
    `description: ${first} ${second}`,
    "repro: unverified",
    "---",
    "",
    `# ${item.title}`,
    "",
    first,
    second,
    "",
    `- CVE IDs: ${cves}`,
    `- Link: ${item.link}`,
    `- Tags: ${tags}`,
    `- Published: ${published}`,
    "",
    "## Steps to reproduce",
    "",
    reproductionLine(item.link),
    "",
    TEARDOWN_NOTE,
    "",
    attributionLine(item.link),
    "",
  ].join("\n");
}

export function isRadarLink(link) {
  try {
    const url = new URL(String(link));
    return url.protocol === "https:" && url.hostname === RADAR_HOST;
  } catch {
    return false;
  }
}

function licenseProblems(text, item) {
  const problems = [];
  const cap = renderSkill(item).length;
  if (text.length > cap) {
    problems.push(`body length ${text.length} exceeds harvester cap ${cap}`);
  }
  if (text.toLowerCase().includes("content:encoded")) {
    problems.push("contains content:encoded");
  }
  if (/(^|[^A-Za-z])CDATA([^A-Za-z]|$)/.test(text)) {
    problems.push("contains CDATA");
  }
  if (/<!--|<\/?[A-Za-z][^>\n]*>/.test(text)) {
    problems.push("contains an HTML tag");
  }
  if (!text.includes(attributionLine(item.link))) {
    problems.push("missing attribution line");
  }
  if (!text.includes(reproductionLine(item.link))) {
    problems.push("missing reproduction line");
  }
  if (typeof item.link !== "string" || !text.includes(item.link)) {
    problems.push("missing index link");
  }
  if (!isRadarLink(item.link)) {
    problems.push("index link is not on radar.cloudflare.com");
  }
  return problems;
}

function rel(tree, path) {
  if (tree === TREE) return relative(ROOT, path);
  return path;
}

export async function checkTree(tree) {
  const results = [];
  const indexPath = join(tree, "index.json");
  let index;
  try {
    index = JSON.parse(await readFile(indexPath, "utf8"));
  } catch (error) {
    results.push({
      file: rel(tree, indexPath),
      pass: false,
      reasons: [`index.json is not readable JSON (${error.message})`],
    });
    return results;
  }

  const indexProblems = [];
  if (typeof index.feed !== "string" || index.feed.length === 0) indexProblems.push("feed is empty");
  if (!(index.etag === null || typeof index.etag === "string")) indexProblems.push("etag must be a string or null");
  if (!Array.isArray(index.items) || index.items.length === 0) indexProblems.push("items must be a non-empty array");
  results.push({
    file: rel(tree, indexPath),
    pass: indexProblems.length === 0,
    reasons: indexProblems,
  });
  if (!Array.isArray(index.items)) return results;

  const bySlug = new Map();
  for (const item of index.items) {
    const slug = item && item.slug;
    if (typeof slug !== "string" || slug.length === 0) {
      results.push({ file: rel(tree, indexPath), pass: false, reasons: ["item slug is missing"] });
      continue;
    }
    if (bySlug.has(slug)) {
      results.push({ file: rel(tree, indexPath), pass: false, reasons: [`duplicate slug ${slug}`] });
      continue;
    }
    bySlug.set(slug, item);
  }

  let entries = [];
  try {
    entries = await readdir(tree, { withFileTypes: true });
  } catch (error) {
    results.push({ file: rel(tree, tree), pass: false, reasons: [error.message] });
    return results;
  }

  const dirs = entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name);
  const files = entries.filter((entry) => entry.isFile()).map((entry) => entry.name);
  for (const name of files.filter((name) => name !== "index.json").sort()) {
    results.push({
      file: rel(tree, join(tree, name)),
      pass: false,
      reasons: ["unexpected file; the harvest writes only index.json and slug/SKILL.md"],
    });
  }
  for (const slug of dirs.filter((slug) => !bySlug.has(slug)).sort()) {
    results.push({
      file: rel(tree, join(tree, slug)),
      pass: false,
      reasons: ["directory is not an index item"],
    });
  }
  for (const slug of [...bySlug.keys()].filter((slug) => !dirs.includes(slug)).sort()) {
    results.push({
      file: rel(tree, join(tree, slug, "SKILL.md")),
      pass: false,
      reasons: ["missing SKILL.md"],
    });
  }

  for (const slug of [...bySlug.keys()].filter((slug) => dirs.includes(slug)).sort()) {
    const item = bySlug.get(slug);
    const skillDir = join(tree, slug);
    const skillPath = join(skillDir, "SKILL.md");
    const label = rel(tree, skillPath);
    const children = await readdir(skillDir, { withFileTypes: true });
    const childNames = children.map((entry) => entry.name).sort();
    const reasons = [];
    if (childNames.length !== 1 || childNames[0] !== "SKILL.md") {
      reasons.push(`directory contains ${childNames.join(", ") || "nothing"}; only SKILL.md is allowed`);
    }
    const skillFile = children.find((entry) => entry.name === "SKILL.md");
    if (!skillFile || !skillFile.isFile()) {
      reasons.push("SKILL.md is missing");
      results.push({ file: label, pass: false, reasons });
      continue;
    }
    const text = await readFile(skillPath, "utf8");
    const meta = parseFrontmatter(text);
    if (!text.startsWith("---\n")) reasons.push("has no frontmatter");
    if (item.name !== `zero-wire-${slug}`) reasons.push(`index name is ${item.name}, expected zero-wire-${slug}`);
    if (meta.name !== item.name) reasons.push(`frontmatter name is ${meta.name || "missing"}`);
    if (typeof meta.description !== "string" || meta.description.length === 0) {
      reasons.push("frontmatter description is empty");
    }
    if (!isReproState(meta.repro) || meta.repro !== "unverified") {
      reasons.push(`repro is ${meta.repro || "missing"}`);
    }
    reasons.push(...licenseProblems(text, item));
    results.push({ file: label, pass: reasons.length === 0, reasons });
  }
  return results;
}

function formatResult(row) {
  const status = row.pass ? "PASS" : "FAIL";
  const why = row.reasons.length > 0 ? `: ${row.reasons.join("; ")}` : "";
  return `${status} ${row.file}${why}`;
}

const CANARY = {
  slug: "canary-brief",
  name: "zero-wire-canary-brief",
  title: "Canary Brief",
  link: "https://radar.cloudflare.com/security/zero-wire/canary-brief",
  pubDate: "Wed, 04 Nov 2026 00:00:00 GMT",
  cves: ["CVE-2026-10001"],
  tags: [{ term: "Needs attention", domain: "https://radar.cloudflare.com/security/zero-wire/tag/needs-attention" }],
};

async function writeFixture(dir, item, text) {
  const index = {
    feed: "https://radar.cloudflare.com/security/zero-wire/rss",
    etag: null,
    items: [item],
  };
  await writeFile(join(dir, "index.json"), `${JSON.stringify(index, null, 2)}\n`);
  const skillDir = join(dir, item.slug);
  await mkdir(skillDir, { recursive: true });
  await writeFile(join(skillDir, "SKILL.md"), text);
}

async function withBadSkill(mutate) {
  const dir = await mkdtemp(join(tmpdir(), "zw-license-"));
  try {
    const item = structuredClone(CANARY);
    let text = renderSkill(item);
    const edited = mutate(item, text);
    if (edited.text !== undefined) text = edited.text;
    const nextItem = edited.item || item;
    if (edited.text === undefined && edited.item) text = renderSkill(nextItem);
    await writeFixture(dir, nextItem, text);
    const results = await checkTree(dir);
    const skill = results.find((row) => row.file.endsWith(`${nextItem.slug}/SKILL.md`));
    assert.ok(skill, "negative fixture did not check a skill");
    return skill;
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("attribution and reproduction lines match harvest-zero-wire.py", () => {
  const index = JSON.parse(readFileSync(join(TREE, "index.json"), "utf8"));
  const stdout = execFileSync("python3", ["-c", `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("h", "scripts/harvest-zero-wire.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
items = json.load(sys.stdin)
json.dump({
    "canary_attribution": h.attribution_line(items[0]["link"]),
    "canary_reproduction": h.reproduction_line(items[0]["link"]),
    "renders": {item["slug"]: h.render_skill(item) for item in items},
}, sys.stdout)
`], { cwd: ROOT, encoding: "utf8", input: JSON.stringify([CANARY, ...index.items]) });
  const got = JSON.parse(stdout);
  assert.equal(attributionLine(CANARY.link), got.canary_attribution);
  assert.equal(reproductionLine(CANARY.link), got.canary_reproduction);
  assert.equal(renderSkill(CANARY), got.renders[CANARY.slug]);
  for (const item of index.items) {
    assert.equal(renderSkill(item), got.renders[item.slug], item.slug);
  }
});

test("cloudflare zero-wire skills pass the frontmatter and CC BY-NC 4.0 checks", async () => {
  const results = await checkTree(TREE);
  for (const row of results) console.log(formatResult(row));
  const failed = results.filter((row) => !row.pass);
  assert.equal(failed.length, 0, failed.map(formatResult).join("\n"));
  const skills = results.filter((row) => row.file.endsWith("/SKILL.md"));
  assert.equal(skills.length, 13);
});

test("a harvester render in a temp tree passes the license guard", async () => {
  const skill = await withBadSkill(() => ({}));
  assert.equal(skill.pass, true, skill.reasons.join("; "));
});

test("content:encoded fails the license guard", async () => {
  const skill = await withBadSkill((_item, text) => ({
    text: text.replace("Cloudflare Radar", "content:encoded"),
  }));
  assert.equal(skill.pass, false);
  assert.ok(skill.reasons.includes("contains content:encoded"), skill.reasons.join("; "));
});

test("an HTML tag fails the license guard", async () => {
  const skill = await withBadSkill((_item, text) => ({
    text: text.replaceAll("published", "<i>x</i>"),
  }));
  assert.equal(skill.pass, false);
  assert.ok(skill.reasons.includes("contains an HTML tag"), skill.reasons.join("; "));
});

test("CDATA fails the license guard", async () => {
  const skill = await withBadSkill((_item, text) => ({
    text: text.replaceAll("published", "CDATA----"),
  }));
  assert.equal(skill.pass, false);
  assert.ok(skill.reasons.includes("contains CDATA"), skill.reasons.join("; "));
});

test("a body longer than render_skill fails the license guard", async () => {
  const skill = await withBadSkill((_item, text) => ({
    text: `${text}\nCopied feed body that the harvester does not store.\n`,
  }));
  assert.equal(skill.pass, false);
  assert.ok(skill.reasons.some((reason) => reason.startsWith("body length")), skill.reasons.join("; "));
});

test("a loosened attribution line fails the license guard", async () => {
  const skill = await withBadSkill((_item, text) => ({
    text: text.replace(ATTRIBUTION, "License: CC BY-NC 4.0"),
  }));
  assert.equal(skill.pass, false);
  assert.ok(skill.reasons.includes("missing attribution line"), skill.reasons.join("; "));
  assert.equal(skill.reasons.some((reason) => reason.startsWith("body length")), false, skill.reasons.join("; "));
});

test("a loosened reproduction line fails the license guard", async () => {
  const skill = await withBadSkill((_item, text) => ({
    text: text.replace("\u2014", "-"),
  }));
  assert.equal(skill.pass, false);
  assert.ok(skill.reasons.includes("missing reproduction line"), skill.reasons.join("; "));
});

test("a skill link that does not match index.json fails the license guard", async () => {
  const skill = await withBadSkill((_item, text) => ({
    text: text.replaceAll(CANARY.link, "https://radar.cloudflare.com/security/zero-wire/other-brief"),
  }));
  assert.equal(skill.pass, false);
  assert.ok(skill.reasons.includes("missing index link"), skill.reasons.join("; "));
  assert.ok(skill.reasons.includes("missing attribution line"), skill.reasons.join("; "));
});

test("an index link outside radar.cloudflare.com fails the license guard", async () => {
  const skill = await withBadSkill((item) => ({
    item: { ...item, link: "https://radar.cloudflare.com.evil.example/zero-wire/canary-brief" },
  }));
  assert.equal(skill.pass, false);
  assert.ok(skill.reasons.includes("index link is not on radar.cloudflare.com"), skill.reasons.join("; "));
});
