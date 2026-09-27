/**
 * dsh-skill-rag — retrieval over the skill library.
 *
 * WHY THIS EXISTS
 * `skill-select.sh` scored skills by literal keyword overlap. That misses paraphrase:
 * recon saying "the endpoint takes a file parameter and resolves it" should surface the
 * LFI skill even though the words never co-occur. Red-MIRROR's published gain over a
 * non-retrieval multi-agent baseline comes from exactly this retrieval step.
 *
 * THREE LAYERS, cheapest first
 *   1. TF-IDF            -- always available, no dependencies, no network.
 *   2. Concept expansion -- a curated security thesaurus. This is what fixes the classic
 *      miss the user hit: a query saying "server fetches a URL" contains none of the
 *      letters "ssrf", and vice versa. Offline and deterministic, so CI gets it too.
 *   3. Embeddings        -- OPTIONAL rerank against any OpenAI-compatible /embeddings
 *      endpoint. Real semantic matching, disk-cached, and silently skipped when no
 *      endpoint is configured or the call fails. Layers 1-2 always run, so retrieval
 *      never depends on the network.
 *
 * It returns EVIDENCE, not a decision -- JEV still picks the skill, per AGENTS.md rule 2.
 */

import { readFile, readdir, stat } from "node:fs/promises";
import { join, extname, basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { mkdirSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";

export const name = "skill-rag";
export const inject = ["tools"];

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..");

const STOP = new Set(
  "a an the and or of to in for on with is are be by as at from that this it its if then than into over under not no any all can may must should would could will your you our their they them he she we us i".split(" ")
);

/**
 * Security concept thesaurus. If ANY surface form appears in the query, every form
 * (including the canonical label) is added to it. This is the offline half of semantic
 * matching, and it is deliberately curated rather than generated: a wrong synonym here
 * silently mis-ranks every hunt.
 */
export const CONCEPTS = {
  ssrf: ["ssrf", "server-side request forgery", "server fetches a url", "url parameter fetch", "webhook url", "remote url fetch", "outbound http request", "callback url", "internal request", "metadata endpoint", "image url fetch", "import from url"],
  idor: ["idor", "insecure direct object reference", "object reference", "id parameter", "numeric identifier in the query", "another user's record", "horizontal access", "guessable identifier", "swap the id"],
  xss: ["xss", "cross-site scripting", "script execution", "html injection", "reflected input", "dom sink", "innerhtml", "javascript executes"],
  sqli: ["sqli", "sql injection", "database query injection", "sql error", "union select", "boolean blind", "time based", "tautology"],
  lfi: ["lfi", "path traversal", "directory traversal", "local file inclusion", "read local file", "file parameter", "resolves it on the filesystem", "directory escape", "dot dot slash"],
  rce: ["rce", "remote code execution", "command injection", "shell injection", "os command", "code execution"],
  authz: ["authorization", "access control", "privilege escalation", "missing auth", "role check", "permission", "broken access"],
  csrf: ["csrf", "cross-site request forgery", "state changing request", "no anti-csrf token", "forged request"],
  xxe: ["xxe", "xml external entity", "xml parser", "doctype entity", "bill of materials upload"],
  redirect: ["open redirect", "unvalidated redirect", "redirect parameter", "next parameter", "return url", "destination parameter"],
  takeover: ["subdomain takeover", "dangling cname", "unclaimed bucket", "nxdomain", "third party host"],
  cache: ["cache poisoning", "web cache deception", "cache key", "x-cache", "unkeyed input", "cdn cache"],
  jwt: ["jwt", "json web token", "algorithm confusion", "alg none", "token signature", "bearer token"],
  oauth: ["oauth", "oidc", "sso", "authorization code", "redirect uri", "identity provider", "saml"],
  deserialization: ["deserialization", "unserialize", "object injection", "pickle", "java serialized", "viewstate"],
  ssti: ["ssti", "template injection", "template engine", "jinja", "twig", "freemarker", "expression language"],
  businesslogic: ["business logic", "workflow bypass", "price manipulation", "quantity tampering", "coupon abuse", "race condition", "state machine"],
  ratelimit: ["rate limit", "otp brute force", "enumeration", "account lockout", "credential stuffing"],
  graphql: ["graphql", "introspection", "mutation", "resolver", "node id"],
  prototypepollution: ["prototype pollution", "proto pollution", "object merge", "deep merge", "constructor prototype"],
};

/** Expand a query with every surface form of any concept it touches. */
export function expandQuery(query) {
  const q = String(query || "").toLowerCase();
  const added = [];
  for (const [canon, forms] of Object.entries(CONCEPTS)) {
    if (forms.some((f) => q.includes(f))) {
      for (const f of forms) {
        if (!q.includes(f)) added.push(f);
      }
      if (!q.includes(canon)) added.push(canon);
    }
  }
  return { query: `${query} ${added.join(" ")}`.trim(), concepts_added: added, matched_concepts: matchedConcepts(query) };
}

export function matchedConcepts(query) {
  const q = String(query || "").toLowerCase();
  return Object.entries(CONCEPTS)
    .filter(([, forms]) => forms.some((f) => q.includes(f)))
    .map(([canon]) => canon);
}

export function tokenize(text) {
  return String(text || "")
    .toLowerCase()
    .replace(/[^a-z0-9_./-]+/g, " ")
    .split(/\s+/)
    .filter((t) => t.length > 1 && !STOP.has(t));
}

export function buildIndex(docs) {
  const df = new Map();
  const entries = docs.map((d) => {
    const tf = new Map();
    for (const t of tokenize(d.text)) tf.set(t, (tf.get(t) || 0) + 1);
    for (const t of tf.keys()) df.set(t, (df.get(t) || 0) + 1);
    return { id: d.id, path: d.path, tf };
  });
  return { entries, df, n: docs.length };
}

export function rank(index, query, k = 8) {
  const qTerms = [...new Set(tokenize(query))];
  if (!qTerms.length) return [];
  const N = index.n || 1;
  const scored = index.entries.map((e) => {
    let score = 0;
    const matched = [];
    for (const t of qTerms) {
      const tf = e.tf.get(t);
      if (!tf) continue;
      const idf = Math.log(1 + N / (1 + (index.df.get(t) || 0)));
      score += (1 + Math.log(tf)) * idf;
      matched.push(t);
    }
    return { id: e.id, path: e.path, score: Number(score.toFixed(3)), matched_terms: matched };
  });
  return scored.filter((s) => s.score > 0).sort((a, b) => b.score - a.score).slice(0, k);
}

export function cosine(a, b) {
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i += 1) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (!na || !nb) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

// ---------------------------------------------------------------- embeddings

/** Embedding endpoint config, or null when unconfigured. */
export function embeddingConfig() {
  const base = process.env.EMBEDDINGS_URL || (process.env.OPENAI_BASE_URL ? `${process.env.OPENAI_BASE_URL.replace(/\/$/, "")}/embeddings` : null);
  const key = process.env.EMBEDDINGS_API_KEY || process.env.OPENAI_API_KEY || null;
  const url = base || (key ? "https://api.openai.com/v1/embeddings" : null);
  if (!url) return null;
  return { url, key, model: process.env.EMBEDDINGS_MODEL || "text-embedding-3-small" };
}

const CACHE_DIR = join(tmpdir(), "bughive-embeddings");

function cacheKey(model, text) {
  return createHash("sha256").update(`${model}\u0000${text}`).digest("hex");
}

function cacheGet(model, text) {
  try {
    const f = join(CACHE_DIR, cacheKey(model, text) + ".json");
    if (!existsSync(f)) return null;
    return JSON.parse(readFileSync(f, "utf8"));
  } catch {
    return null;
  }
}

function cacheSet(model, text, vec) {
  try {
    mkdirSync(CACHE_DIR, { recursive: true });
    writeFileSync(join(CACHE_DIR, cacheKey(model, text) + ".json"), JSON.stringify(vec));
  } catch {
    /* cache is best-effort */
  }
}

/**
 * Embed texts, using the disk cache. Returns null on any failure so callers fall back to
 * lexical retrieval rather than erroring a hunt.
 */
export async function embed(texts, cfg) {
  if (!cfg) return null;
  const out = new Array(texts.length).fill(null);
  const missing = [];
  texts.forEach((t, i) => {
    const hit = cacheGet(cfg.model, t);
    if (hit) out[i] = hit;
    else missing.push({ i, t });
  });
  if (missing.length) {
    try {
      const res = await fetch(cfg.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(cfg.key ? { Authorization: `Bearer ${cfg.key}` } : {}),
        },
        body: JSON.stringify({ model: cfg.model, input: missing.map((m) => m.t) }),
      });
      if (!res.ok) return null;
      const data = await res.json();
      const vecs = (data.data || []).map((d) => d.embedding);
      if (vecs.length !== missing.length) return null;
      missing.forEach((m, idx) => {
        out[m.i] = vecs[idx];
        cacheSet(cfg.model, m.t, vecs[idx]);
      });
    } catch {
      return null;
    }
  }
  return out.some((v) => v === null) ? null : out;
}

async function loadDocs(root) {
  const docs = [];
  async function walk(dir, tier) {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = join(dir, e.name);
      if (e.isDirectory()) await walk(p, tier);
      else if (extname(e.name).toLowerCase() === ".md" && e.name !== "README.md" && e.name !== "_schema.md") {
        try {
          const st = await stat(p);
          if (st.size > 400_000) continue;
          docs.push({ id: `${tier}/${basename(e.name, ".md")}`, path: p, text: await readFile(p, "utf8") });
        } catch {
          /* skip unreadable */
        }
      }
    }
  }
  await walk(join(root, "seeds"), "seeds");
  await walk(join(root, "learned"), "learned");
  return docs;
}

export function apply(ctx, config = {}) {
  const cfg = { skillsRoot: join(REPO, "skills"), useEmbeddings: true, ...config };
  let index = null;
  let docs = null;

  async function ensureIndex() {
    if (index) return index;
    docs = await loadDocs(cfg.skillsRoot);
    index = buildIndex(docs);
    return index;
  }

  ctx.tools.register({
    name: "retrieve_skills",
    description:
      "Rank the skill library against evidence. Three layers: TF-IDF always; curated security concept expansion for synonymy ('server fetches a URL' -> SSRF), which is offline and deterministic; and an optional embeddings rerank when EMBEDDINGS_URL/OPENAI_API_KEY is configured. Returns ranked candidates as EVIDENCE — JEV still chooses the skill.",
    parameters: {
      type: "object",
      properties: {
        query: { type: "string", description: "Recon evidence or a behavioural description." },
        k: { type: "number", description: "How many candidates (default 8)." },
        useEmbeddings: { type: "boolean", description: "Override the configured default." },
      },
      required: ["query"],
    },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute(args) {
      const idx = await ensureIndex();
      const k = Number.isFinite(args.k) ? args.k : 8;
      const expanded = expandQuery(args.query);

      // Layer 1 + 2
      let candidates = rank(idx, expanded.query, Math.max(k * 3, 20));

      // Layer 3 (optional)
      let embeddingsUsed = "not-configured";
      const wantEmb = args.useEmbeddings !== false && cfg.useEmbeddings;
      const ecfg = wantEmb ? embeddingConfig() : null;
      if (ecfg) {
        const vecs = await embed([expanded.query, ...candidates.map((c) => docs.find((d) => d.id === c.id)?.text || "")], ecfg);
        if (vecs) {
          const [qv, ...dv] = vecs;
          candidates = candidates.map((c, i) => {
            const sim = dv[i] ? cosine(qv, dv[i]) : 0;
            return { ...c, embedding_similarity: Number(sim.toFixed(4)), score: Number((c.score + sim * 10).toFixed(3)) };
          });
          candidates.sort((a, b) => b.score - a.score);
          embeddingsUsed = "used";
        } else {
          embeddingsUsed = "unavailable (call failed) — fell back to lexical";
        }
      } else if (wantEmb) {
        embeddingsUsed = "not-configured (set EMBEDDINGS_URL or OPENAI_API_KEY to enable)";
      }

      return JSON.stringify({
        indexed_skills: idx.n,
        matched_concepts: expanded.matched_concepts,
        concept_terms_added: expanded.concepts_added.length,
        embeddings: embeddingsUsed,
        candidates: candidates.slice(0, k),
        note: candidates.length
          ? "Retrieval evidence only. JEV selects the skill."
          : "No lexical or conceptual overlap. Describe the observed behaviour instead.",
      });
    },
  });

  ctx.tools.register({
    name: "skill_rag_reload",
    description: "Rebuild the skill index (call after adding skills to skills/learned/).",
    parameters: { type: "object", properties: {} },
    output: { schema: { type: "string" }, render: (_a, v) => [{ type: "text", text: v }] },
    async execute() {
      index = null;
      const idx = await ensureIndex();
      return JSON.stringify({ reloaded: true, indexed_skills: idx.n });
    },
  });

  console.log("[skill-rag] registered: retrieve_skills, skill_rag_reload (tf-idf + concepts + optional embeddings)");
}
