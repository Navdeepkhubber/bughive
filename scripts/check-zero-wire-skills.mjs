/**
 * Loader check for skills/cloudflare-zero-wire.
 *
 * Frontmatter is parsed with the same rules as parseFrontmatter in
 * plugins/dsh-skill-loader/index.js. `repro` must be a state that loader
 * accepts (`isReproState`) and must be `unverified`, which is what
 * scripts/harvest-zero-wire.py writes. No network.
 */
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { isReproState } from "../plugins/dsh-repro-steps/parse.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const TREE = join(ROOT, "skills", "cloudflare-zero-wire");

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

test("cloudflare zero-wire skills pass the frontmatter loader check", async () => {
  const entries = await readdir(TREE, { withFileTypes: true });
  const names = entries.map((entry) => entry.name).sort();
  assert.ok(names.includes("index.json"), "skills/cloudflare-zero-wire/index.json is missing");

  const index = JSON.parse(await readFile(join(TREE, "index.json"), "utf8"));
  assert.equal(typeof index.feed, "string");
  assert.ok(index.feed.length > 0, "index feed is empty");
  assert.ok(index.etag === null || typeof index.etag === "string", "index etag must be a string or null");
  assert.ok(Array.isArray(index.items) && index.items.length > 0, "index items must be a non-empty array");

  const bySlug = new Map();
  for (const item of index.items) {
    assert.equal(typeof item.slug, "string", "item slug");
    assert.equal(item.name, `zero-wire-${item.slug}`);
    assert.equal(bySlug.has(item.slug), false, `duplicate slug ${item.slug}`);
    bySlug.set(item.slug, item);
  }

  const dirs = entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  const files = entries.filter((entry) => entry.isFile()).map((entry) => entry.name).sort();
  assert.deepEqual(files, ["index.json"]);
  assert.deepEqual(dirs, [...bySlug.keys()].sort());

  for (const slug of dirs) {
    const skillDir = join(TREE, slug);
    const children = await readdir(skillDir, { withFileTypes: true });
    assert.deepEqual(
      children.map((entry) => entry.name).sort(),
      ["SKILL.md"],
      `${slug} may only contain SKILL.md`,
    );
    const skillFile = children.find((entry) => entry.name === "SKILL.md");
    assert.equal(skillFile.isFile(), true, `${slug}/SKILL.md`);

    const text = await readFile(join(skillDir, "SKILL.md"), "utf8");
    const meta = parseFrontmatter(text);
    const label = `skills/cloudflare-zero-wire/${slug}/SKILL.md`;
    assert.ok(text.startsWith("---\n"), `${label} has no frontmatter`);
    assert.equal(meta.name, bySlug.get(slug).name, `${label} name`);
    assert.equal(typeof meta.description, "string");
    assert.ok(meta.description.length > 0, `${label} description is empty`);
    assert.equal(isReproState(meta.repro), true, `${label} repro is not a loader state: ${meta.repro}`);
    assert.equal(meta.repro, "unverified", `${label} repro`);
  }
});
