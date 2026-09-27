/**
 * dsh-asset-dedup — cluster near-identical assets so effort goes to unique surface.
 *
 * WHY THIS EXISTS
 * Large scopes are full of clones: `stage0001-dev.example.com`, three copies of the same
 * app behind different hostnames, the same marketing page on twenty subdomains. Testing
 * each one individually burns the whole budget, and reporting the same bug against each
 * looks like spam to a triager. The published approach (XBOW) uses SimHash over content
 * plus screenshot perceptual hashing to group assets, and treats a finding in one member
 * as a lead for the whole family.
 *
 * This implements the content half: 64-bit SimHash over k-shingles of the normalised body,
 * clustered by Hamming distance. Screenshot hashing is deliberately NOT attempted here --
 * it needs an image decoder and a browser, and pretending to do it with a hash of the
 * file bytes would silently fail. Do that in the browser validator instead.
 *
 * Pure functions are exported so the clustering is testable without any network.
 */

import { readFile, readdir, stat } from "node:fs/promises";
import { join, extname } from "node:path";

export const name = "asset-dedup";
export const inject = ["tools"];

const FNV_OFFSET = 14695981039346656037n;
const FNV_PRIME = 1099511628211n;
const MASK64 = (1n << 64n) - 1n;

/** 64-bit FNV-1a. */
export function fnv1a64(str) {
  let h = FNV_OFFSET;
  for (let i = 0; i < str.length; i += 1) {
    h ^= BigInt(str.charCodeAt(i));
    h = (h * FNV_PRIME) & MASK64;
  }
  return h;
}

/** Normalise a response body so boilerplate differences do not defeat clustering. */
export function normalizeForHash(text) {
  return String(text || "")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/\b\d{4}-\d{2}-\d{2}[T ][\d:.]+Z?\b/g, " ")
    .replace(/\b[0-9a-f]{16,}\b/gi, " ")
    .replace(/\b\d+\b/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

/** Word k-shingles give much more stable similarity than single tokens. */
export function shingles(text, k = 4) {
  const words = normalizeForHash(text).split(" ").filter(Boolean);
  if (words.length <= k) return [words.join(" ")];
  const out = [];
  for (let i = 0; i + k <= words.length; i += 1) out.push(words.slice(i, i + k).join(" "));
  return out;
}

/** 64-bit SimHash over the shingle set. */
export function simhash(text, k = 4) {
  const bits = 64;
  const v = new Array(bits).fill(0);
  for (const sh of shingles(text, k)) {
    const h = fnv1a64(sh);
    for (let i = 0; i < bits; i += 1) {
      const bit = (h >> BigInt(i)) & 1n;
      v[i] += bit === 1n ? 1 : -1;
    }
  }
  let out = 0n;
  for (let i = 0; i < bits; i += 1) if (v[i] > 0) out |= 1n << BigInt(i);
  return out;
}

export function popcount64(x) {
  let n = 0;
  let v = x & MASK64;
  while (v) {
    v &= v - 1n;
    n += 1;
  }
  return n;
}

export function hamming(a, b) {
  return popcount64(a ^ b);
}

export function toHex64(x) {
  return x.toString(16).padStart(16, "0");
}

/**
 * Cluster items by Hamming distance. `items` = [{id, text}].
 * Greedy single-pass clustering: the first member becomes the representative.
 */
export function clusterBySimhash(items, threshold = 6, k = 4) {
  const hashed = items.map((it) => ({ id: it.id, hash: simhash(it.text, k) }));
  const clusters = [];
  for (const h of hashed) {
    let placed = false;
    for (const c of clusters) {
      const d = hamming(h.hash, c.hash);
      if (d <= threshold) {
        c.members.push({ id: h.id, distance: d, hash: toHex64(h.hash) });
        placed = true;
        break;
      }
    }
    if (!placed) {
      clusters.push({ hash: h.hash, members: [{ id: h.id, distance: 0, hash: toHex64(h.hash) }] });
    }
  }
  return clusters.map((c) => ({
    representative: c.members[0].id,
    size: c.members.length,
    simhash: toHex64(c.hash),
    members: c.members,
  }));
}

/** Population count for arbitrary-width BigInt (no 64-bit mask). */
export function popcount(x) {
  let n = 0;
  let v = x < 0n ? -x : x;
  while (v) {
    v &= v - 1n;
    n += 1;
  }
  return n;
}

/** Hamming distance between two hex-encoded perceptual hashes of any width. */
export function hammingHex(a, b, bits = 256) {
  try {
    return popcount(BigInt(`0x${String(a)}`) ^ BigInt(`0x${String(b)}`));
  } catch {
    return bits; // unparseable => maximally distant, never a silent match
  }
}

/**
 * Cluster items by perceptual image hash. `items` = [{id, dhash}].
 * dHash is robust to scaling and compression, so visually identical pages on different
 * hostnames land in the same cluster even though their HTML differs.
 */
export function clusterByHashes(items, threshold = 8) {
  const clusters = [];
  for (const it of items) {
    if (!it || !it.dhash) continue;
    let placed = false;
    for (const c of clusters) {
      const d = hammingHex(it.dhash, c.hash);
      if (d <= threshold) {
        c.members.push({ id: it.id, distance: d, dhash: it.dhash });
        placed = true;
        break;
      }
    }
    if (!placed) {
      clusters.push({ hash: it.dhash, members: [{ id: it.id, distance: 0, dhash: it.dhash }] });
    }
  }
  return clusters.map((c) => ({
    representative: c.members[0].id,
    size: c.members.length,
    dhash: c.hash,
    members: c.members,
  }));
}

const TEXT_EXT = new Set([".html", ".htm", ".json", ".txt", ".xml", ".js"]);

async function collect(paths) {
  const out = [];
  async function walk(p) {
    let st;
    try {
      st = await stat(p);
    } catch {
      return;
    }
    if (st.isDirectory()) {
      for (const e of await readdir(p, { withFileTypes: true })) await walk(join(p, e.name));
    } else if (TEXT_EXT.has(extname(p).toLowerCase())) {
      out.push(p);
    }
  }
  for (const p of paths) await walk(p);
  return out;
}

export function apply(ctx) {
  ctx.tools.register({
    name: "dedup_assets",
    description:
      "Cluster near-identical responses (clone/staging hosts, repeated apps) by 64-bit SimHash over word shingles. Give it a response-cache directory or an inline JSON array of {id,text}. Use the representative of each cluster as the real target and treat a finding in one member as a lead for its siblings.",
    parameters: {
      type: "object",
      properties: {
        paths: { type: "string", description: "Files/directories of cached responses, one per line." },
        items: { type: "string", description: "Alternative: JSON array of {id, text}." },
        threshold: { type: "number", description: "Max Hamming distance to consider a clone (default 6 of 64)." },
      },
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      let items = [];
      if (args.items) {
        try {
          const parsed = JSON.parse(args.items);
          if (!Array.isArray(parsed)) throw new Error("not an array");
          items = parsed
            .filter((x) => x && typeof x.text === "string")
            .map((x) => ({ id: String(x.id ?? x.url ?? "item"), text: x.text }));
        } catch (e) {
          return JSON.stringify({ error: `items must be a JSON array of {id,text}: ${e.message}` });
        }
      } else {
        const paths = String(args.paths || "")
          .split(/[\n,]/)
          .map((s) => s.trim())
          .filter(Boolean);
        if (!paths.length) return JSON.stringify({ error: "supply paths or items", clusters: [] });
        const files = await collect(paths);
        for (const f of files) {
          try {
            items.push({ id: f, text: await readFile(f, "utf8") });
          } catch {
            /* skip unreadable */
          }
        }
      }
      if (!items.length) return JSON.stringify({ clusters: [], note: "no inputs found" });

      const threshold = Number.isFinite(args.threshold) ? args.threshold : 6;
      const clusters = clusterBySimhash(items, threshold);
      const duplicates = clusters.reduce((n, c) => n + (c.size - 1), 0);
      return JSON.stringify({
        inputs: items.length,
        clusters: clusters.length,
        duplicate_assets: duplicates,
        saved_effort_pct: items.length ? Math.round((duplicates / items.length) * 100) : 0,
        groups: clusters.filter((c) => c.size > 1).slice(0, 100),
        unique_representatives: clusters.map((c) => c.representative).slice(0, 200),
      });
    },
  });

  ctx.tools.register({
    name: "dedup_by_hash",
    description:
      "Cluster assets by perceptual image hash (dHash from screenshot_hash/hash_images). Use together with dedup_assets: content hashing catches identical HTML, image hashing catches visually identical apps whose markup differs.",
    parameters: {
      type: "object",
      properties: {
        items: { type: "string", description: "JSON array of {id, dhash}." },
        threshold: { type: "number", description: "Max Hamming distance out of 256 (default 8, ~3%)." },
      },
      required: ["items"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      let items;
      try {
        items = JSON.parse(args.items);
        if (!Array.isArray(items)) throw new Error("not an array");
      } catch (e) {
        return JSON.stringify({ error: `items must be a JSON array of {id,dhash}: ${e.message}` });
      }
      const threshold = Number.isFinite(args.threshold) ? args.threshold : 8;
      const clusters = clusterByHashes(items, threshold);
      const duplicates = clusters.reduce((n, c) => n + (c.size - 1), 0);
      return JSON.stringify({
        inputs: items.filter((i) => i && i.dhash).length,
        clusters: clusters.length,
        duplicate_assets: duplicates,
        groups: clusters.filter((c) => c.size > 1),
      });
    },
  });

  ctx.tools.register({
    name: "simhash_text",
    description: "Hash one text with 64-bit SimHash and return its hex value (for comparing two bodies by hand).",
    parameters: {
      type: "object",
      properties: { text: { type: "string" }, compareTo: { type: "string" } },
      required: ["text"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const a = simhash(args.text);
      if (!args.compareTo) return JSON.stringify({ simhash: toHex64(a) });
      const b = simhash(args.compareTo);
      return JSON.stringify({ a: toHex64(a), b: toHex64(b), hamming: hamming(a, b), of: 64 });
    },
  });

  console.log("[asset-dedup] registered: dedup_assets, simhash_text");
}
