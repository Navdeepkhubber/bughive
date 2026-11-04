#!/usr/bin/env node
/**
 * Per-CVE reproduction enrichment.
 *
 *   node scripts/enrich-repro.mjs --cve CVE-2021-44228
 *   node scripts/enrich-repro.mjs --backfill
 *   node scripts/enrich-repro.mjs --backfill --dry-run
 *
 * Resolves NVD, vendor advisories linked from NVD, GitHub Advisory (GHSA),
 * CISA KEV, the ExploitDB GitLab CSV, PoC-in-GitHub, and local HackerOne
 * harvest files. Writes skills/_index/repro/<ID>.json and a Steps section.
 *
 * Cite or omit: step bullets are paraphrases plus links. Exploit bodies,
 * PoC READMEs, and Cloudflare Zero Wire content:encoded are never copied.
 * NVD unauthenticated limit is 5 requests / 30s; this client waits 7s
 * between NVD calls so a rolling window cannot hold six of them.
 */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const NVD_MIN_INTERVAL_MS = 7000;
export const CACHE_FRESH_MS = 7 * 24 * 60 * 60 * 1000;
export const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
export const KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
export const EDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv";
export const USER_AGENT = "bughive-repro-enrich/1.0 (public-source citation; no exploit execution)";

export const FM_START = "# bughive-repro-start";
export const FM_END = "# bughive-repro-end";
export const BODY_START = "<!-- bughive-repro-start -->";
export const BODY_END = "<!-- bughive-repro-end -->";

export const TIER_A_SKILLS = [
  "skills/seeds/account-takeover.md",
  "skills/seeds/apache-struts.md",
  "skills/seeds/bigip-cisco-vpn.md",
  "skills/seeds/shellshock-webmin.md",
  "skills/seeds/shodan.md",
  "skills/staging/0x002132-skills-bugbounty-bb-local-toolkit.staged.md",
  "skills/staging/0x002132-skills-bugbounty-bug-bounty.staged.md",
  "skills/staging/0x002132-skills-bugbounty-enterprise-vpn-attack.staged.md",
  "skills/staging/0x002132-skills-bugbounty-hunt-aspnet.staged.md",
  "skills/staging/0x002132-skills-bugbounty-hunt-auth-bypass.staged.md",
  "skills/staging/0x002132-skills-bugbounty-hunt-csrf.staged.md",
  "skills/staging/0x002132-skills-bugbounty-hunt-file-upload.staged.md",
  "skills/staging/0x002132-skills-bugbounty-hunt-http-smuggling.staged.md",
  "skills/staging/0x002132-skills-bugbounty-hunt-rce.staged.md",
  "skills/staging/0x002132-skills-bugbounty-hunt-sharepoint.staged.md",
  "skills/staging/0x002132-skills-bugbounty-hunt-xss.staged.md",
  "skills/staging/0x002132-skills-bugbounty-offensive-osint.staged.md",
  "skills/staging/0x002132-skills-bugbounty-redteam-mindset.staged.md",
  "skills/staging/0x002132-skills-bugbounty-vmware-vcenter-attack.staged.md",
  "skills/staging/Gabson0x-bountyforge-skills-bug-bounty.staged.md",
  "skills/staging/ctahok-hermes-bug-bounty-skills-hunt-rce.staged.md",
  "skills/staging/murraywu-Bug-Bounty-Skills-Bug-Bounty-Vulnerability-DB.staged.md",
];

export const CHECKLIST_SKILLS = [
  "skills/staging/0x002132-skills-bugbounty-report-writing.staged.md",
  "skills/staging/Gabson0x-bountyforge-skills-report-writing.staged.md",
  "skills/staging/Gabson0x-bountyforge-skills-web2-vuln-classes.staged.md",
  "skills/staging/Gabson0x-bountyforge-skills-web3-web3-triage-report.staged.md",
  "skills/staging/ctahok-hermes-bug-bounty-skills-hunt-sqli.staged.md",
  "skills/staging/ctahok-hermes-bug-bounty-skills-report-writing.staged.md",
];

export const KEEP_SKILLS = [
  "skills/h1-3771147-mariadb-myisam-bof/SKILL.md",
  "skills/h1-3782405-mariadb-charset-collation-bof/SKILL.md",
  "skills/learned/h1-Improper Access Control - Generic-3533697.md",
];

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const IMPACTS = [
  "remote code execution",
  "arbitrary code execution",
  "arbitrary code",
  "command execution",
  "code execution",
  "denial of service",
  "information disclosure",
  "privilege escalation",
  "authentication bypass",
  "path traversal",
  "directory traversal",
  "cross-site scripting",
  "sql injection",
  "server-side request forgery",
  "improper input validation",
  "memory corruption",
  "buffer overflow",
  "use-after-free",
  "command injection",
  "template injection",
  "deserialization",
  "take over an arbitrary account",
];
const BANNED = [
  /\/bin\/bash/i,
  /\bcurl\b/i,
  /cmd\.exe/i,
  /powershell/i,
  /ProcessBuilder/,
  /wget\s/i,
  /UNION SELECT/i,
  /<script/i,
  /\(\)\s*\{/,
];
const VENDOR_SKIP_HOSTS = new Set([
  "github.com",
  "www.github.com",
  "gitlab.com",
  "www.gitlab.com",
  "nvd.nist.gov",
  "services.nvd.nist.gov",
  "cve.mitre.org",
  "www.cve.org",
  "cve.org",
  "cisa.gov",
  "www.cisa.gov",
  "exploit-db.com",
  "www.exploit-db.com",
  "packetstormsecurity.com",
  "www.packetstormsecurity.com",
  "seclists.org",
  "www.securityfocus.com",
  "securityfocus.com",
  "vuldb.com",
  "exchange.xforce.ibmcloud.com",
  "raw.githubusercontent.com",
  "media.githubusercontent.com",
]);

export function nvdWaitMs(lastAt, now, interval = NVD_MIN_INTERVAL_MS) {
  if (!lastAt) return 0;
  return Math.max(0, interval - (now - lastAt));
}

export function sha256(text) {
  return createHash("sha256").update(text || "", "utf8").digest("hex");
}

export function stripEnrichment(text) {
  return String(text || "")
    .replace(/# bughive-repro-start[\s\S]*?# bughive-repro-end\n?/g, "")
    .replace(/<!-- bughive-repro-start -->[\s\S]*?<!-- bughive-repro-end -->\n?/g, "");
}

function expandSuffix(year, base, suffix) {
  if (suffix.length >= base.length) return `CVE-${year}-${suffix}`;
  return `CVE-${year}-${base.slice(0, base.length - suffix.length)}${suffix}`;
}

export function expandCitedIds(text) {
  const cves = [];
  const ghsas = [];
  const seenC = new Set();
  const seenG = new Set();
  const re = /GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|CVE-(\d{4})-(\d{4,7})((?:\/\d{2,7})*)/gi;
  for (const match of String(text || "").matchAll(re)) {
    const raw = match[0];
    if (raw.toUpperCase().startsWith("CVE-")) {
      const year = match[1];
      const base = match[2];
      const extra = match[3] ? match[3].split("/").filter(Boolean) : [];
      const ids = [`CVE-${year}-${base}`, ...extra.map((suffix) => expandSuffix(year, base, suffix))];
      for (const id of ids) {
        if (seenC.has(id)) continue;
        seenC.add(id);
        cves.push(id);
      }
    } else {
      const id = raw.toLowerCase();
      if (seenG.has(id)) continue;
      seenG.add(id);
      ghsas.push(id);
    }
  }
  return { cves, ghsas };
}

export function rollupRepro(values) {
  const uniq = [...new Set(values.filter(Boolean))];
  if (uniq.length === 0) return "unverified";
  if (uniq.length === 1) return uniq[0];
  return "partial";
}

function impactPhrase(text) {
  const hay = String(text || "").toLowerCase();
  return IMPACTS.find((phrase) => hay.includes(phrase)) || "";
}

function findAllJndi(text) {
  return String(text || "").match(/\$\{jndi:[^}\s]+\}/gi) || [];
}

function acceptableJndi(token) {
  if (!token || token.length > 80) return false;
  if (/base64|command|runtime|bash|cmd/i.test(token)) return false;
  return /^\$\{jndi:[a-z]+:\/\/[a-z0-9._-]+\/[a-z0-9._~/-]*\}$/i.test(token);
}

function firstConcreteInput(record) {
  const sources = [
    ["vendor", record.vendor?.excerpt, record.vendor?.url],
    ["nvd", record.nvd?.description, record.nvd?.detailUrl],
    ["ghsa", record.ghsa?.description, record.ghsa?.html_url],
    ["h1", record.h1?.excerpt, record.h1?.url],
  ];
  for (const [source, text, url] of sources) {
    if (!url) continue;
    for (const token of findAllJndi(text || "")) {
      if (acceptableJndi(token)) return { source, token, url };
    }
  }
  return null;
}

function proseBlob(record) {
  return [record.nvd?.description, record.ghsa?.summary, record.ghsa?.description, record.vendor?.excerpt]
    .filter(Boolean)
    .join("\n");
}

export function listPocUrls(record) {
  const out = [];
  const seen = new Set();
  const add = (url, source) => {
    if (!url || seen.has(url)) return;
    seen.add(url);
    out.push({ url, source });
  };
  const edb = [...(record.exploitdb || [])].sort((a, b) => Number(b.verified) - Number(a.verified));
  for (const row of edb) add(row.url, "exploitdb");
  for (const url of record.nvd?.exploitRefs || []) add(url, "nvd");
  for (const url of record.ghsa?.pocRefs || []) add(url, "ghsa");
  for (const row of record.poc_in_github?.top || []) add(row.html_url, "poc-in-github");
  if (record.h1?.hasText && record.h1.url) add(record.h1.url, "h1");
  return out;
}

export function classifyRecord(record) {
  const status = `${record.nvd?.vulnStatus || ""}`;
  if (/rejected|disputed/i.test(status) || record.ghsa?.withdrawn_at) return "unverified";
  const prose = proseBlob(record);
  const hasProduct = (record.nvd?.products?.length || 0) > 0
    || (record.ghsa?.packages?.length || 0) > 0
    || (record.vendor?.versionPhrases?.length || 0) > 0;
  const versiony = /version|\bbefore\b|\bthrough\b|\baffected\b/i.test(prose);
  const enough = prose.trim().length >= 40 && (hasProduct || versiony);
  const pocs = listPocUrls(record);
  if (pocs.length && enough) return "verified-public";
  if (enough) return "partial";
  if (pocs.length && (hasProduct || prose.trim().length >= 40)) return "partial";
  return "unverified";
}

function cite(label, url) {
  if (!url) return "";
  const safe = String(url).trim().replace(/\)/g, "%29").replace(/\s+/g, "");
  if (!/^https?:\/\//.test(safe)) return "";
  return ` [[${label}](${safe})]`;
}

function withCites(text, pairs) {
  const clean = String(text).replace(/\s+/g, " ").trim();
  const tail = pairs.map(([label, url]) => cite(label, url)).join("");
  if (!tail.trim()) throw new Error(`no citation for: ${clean}`);
  return `${clean}${tail}`;
}

function productSummary(record) {
  const groups = [];
  for (const product of record.nvd?.products || []) {
    const label = [product.vendor, product.product].filter(Boolean).join(" ").replace(/`/g, "");
    const range = (product.range ? `${label} ${product.range}` : label).replace(/`/g, "");
    if (range && !groups.includes(range)) groups.push(range);
    if (groups.length === 3) break;
  }
  return groups;
}

function ghsaPackageSummary(record) {
  return (record.ghsa?.packages || []).slice(0, 3).map((pkg) => {
    const patched = pkg.patched ? `; first patched ${pkg.patched}` : "";
    return `${pkg.ecosystem || "package"} \`${pkg.name}\` ${pkg.range || ""}${patched}`.trim();
  });
}

function prerequisiteBullets(record) {
  const bullets = [];
  const nvdUrl = record.nvd?.detailUrl;
  const products = productSummary(record);
  if (products.length && nvdUrl) {
    const extra = record.nvd.productCount > products.length
      ? ` NVD lists ${record.nvd.productCount} vulnerable CPE matches; showing ${products.length}.`
      : "";
    bullets.push(withCites(`- Affected product from NVD CPE: ${products.join("; ")}.${extra}`, [["nvd", nvdUrl]]));
  }
  const packages = ghsaPackageSummary(record);
  if (packages.length && record.ghsa?.html_url) {
    bullets.push(withCites(`- GitHub Advisory package range: ${packages.join("; ")}.`, [["ghsa", record.ghsa.html_url]]));
  }
  const phrase = record.vendor?.versionPhrases?.[0];
  if (phrase && record.vendor?.url) {
    bullets.push(withCites(`- Vendor advisory states the range \`${phrase}\`.`, [["vendor", record.vendor.url]]));
  }
  if (record.nvd?.cwes?.length && nvdUrl) {
    bullets.push(withCites(`- Weakness: ${record.nvd.cwes.slice(0, 3).join(", ")}.`, [["nvd", nvdUrl]]));
  }
  if (!bullets.length) {
    const url = nvdUrl || record.ghsa?.html_url;
    const label = nvdUrl ? "nvd" : "ghsa";
    bullets.push(withCites("- Not publicly documented beyond the advisory description.", [[label, url]]));
  }
  return bullets;
}

function primaryPoc(record) {
  return listPocUrls(record)[0] || null;
}

function inputBullet(record) {
  const found = firstConcreteInput(record);
  const poc = primaryPoc(record);
  const nvdUrl = record.nvd?.detailUrl;
  const prose = proseBlob(record);
  const impact = impactPhrase(prose);
  if (found) {
    const pairs = [[found.source, found.url]];
    if (poc && poc.url !== found.url) pairs.push([poc.source, poc.url]);
    return withCites(
      `- Deliver a JNDI lookup string such as \`${found.token}\` only where the cited advisory already states that shape. Exact payload variants stay in the linked public PoC and were not copied here.`,
      pairs,
    );
  }
  if (poc && impact && nvdUrl) {
    return withCites(
      `- NVD characterizes the trigger as ${impact}. No concrete request string from the advisory was copied. The linked public PoC is the input source; its body was not copied into this skill.`,
      [["nvd", nvdUrl], [poc.source, poc.url]],
    );
  }
  if (poc) {
    const pairs = [[poc.source, poc.url]];
    if (nvdUrl) pairs.unshift(["nvd", nvdUrl]);
    return withCites(
      "- No concrete request string is stated in the cited advisory text. The linked public PoC is the input source; its body was not copied into this skill.",
      pairs,
    );
  }
  const url = nvdUrl || record.ghsa?.html_url;
  const label = nvdUrl ? "nvd" : "ghsa";
  if (impact) {
    return withCites(
      `- Affected product and an abstract condition are public (${impact}). No concrete request or public PoC URL was found, so none is stated here.`,
      [[label, url]],
    );
  }
  if (prose.trim().length >= 40 && url) {
    return withCites(
      "- The advisory describes the condition in prose. No concrete request was copied, and none was invented.",
      [[label, url]],
    );
  }
  return withCites("- Not publicly available.", [[label, url]]);
}

function expectedBullet(record) {
  const nvdUrl = record.nvd?.detailUrl;
  const ghsaUrl = record.ghsa?.html_url;
  const prose = proseBlob(record);
  const impact = impactPhrase(prose);
  if (/rejected|disputed/i.test(record.nvd?.vulnStatus || "")) {
    return withCites(
      `- NVD vulnStatus is ${record.nvd.vulnStatus}. This skill does not treat a rejected or disputed record as a reproducible bug.`,
      [["nvd", nvdUrl]],
    );
  }
  if (record.ghsa?.withdrawn_at) {
    return withCites(
      `- GitHub Advisory was withdrawn at ${record.ghsa.withdrawn_at}. Withdrawn advisories are not used as a reproduction.`,
      [["ghsa", ghsaUrl]],
    );
  }
  const products = productSummary(record);
  const range = products[0] ? ` Structured affected range: ${products[0]}.` : "";
  const patched = record.ghsa?.packages?.find((pkg) => pkg.patched)?.patched;
  const patchedText = patched ? ` GHSA first patched version: ${patched}.` : "";
  if (impact && (nvdUrl || ghsaUrl)) {
    const pairs = nvdUrl ? [["nvd", nvdUrl]] : [["ghsa", ghsaUrl]];
    if (patched && ghsaUrl && nvdUrl) pairs.push(["ghsa", ghsaUrl]);
    const who = nvdUrl ? "NVD" : "GitHub Advisory";
    return withCites(
      `- Vulnerable builds match the cited range and ${who} characterizes the issue as ${impact}.${range}${patchedText} Patched builds are those outside that range. The advisory text was paraphrased, not copied.`,
      pairs,
    );
  }
  const url = nvdUrl || ghsaUrl;
  const label = nvdUrl ? "nvd" : "ghsa";
  return withCites(
    "- See the public record (abstract only). No concrete vulnerable-versus-patched behavior was copied from the advisory.",
    [[label, url]],
  );
}

function confirmBullet(record) {
  const nvdUrl = record.nvd?.detailUrl;
  const poc = primaryPoc(record);
  const ghsaUrl = record.ghsa?.html_url;
  if (record.repro === "unverified" || (!poc && record.repro !== "partial")) {
    const url = nvdUrl || ghsaUrl;
    const label = nvdUrl ? "nvd" : "ghsa";
    return withCites("- Not possible from public sources.", [[label, url]]);
  }
  if (poc) {
    const pairs = [];
    if (nvdUrl) pairs.push(["nvd", nvdUrl]);
    pairs.push([poc.source, poc.url]);
    return withCites(
      "- Against a disposable lab build inside the cited affected range, compare it with a build at the cited patched version by following the linked public PoC. Do not run untrusted PoC code against production.",
      pairs,
    );
  }
  const url = nvdUrl || ghsaUrl;
  const label = nvdUrl ? "nvd" : "ghsa";
  return withCites(
    "- Not possible from public sources beyond the affected-versus-patched range above. No concrete input was published, so none was invented.",
    [[label, url]],
  );
}

function publicPocLines(record) {
  const lines = [];
  const edb = [...(record.exploitdb || [])].sort((a, b) => Number(b.verified) - Number(a.verified)).slice(0, 3);
  for (const row of edb) {
    lines.push(`- EDB-${row.id} (verified flag ${row.verified ? "1" : "0"}): ${row.url}`);
  }
  const ghsaPoc = (record.ghsa?.pocRefs || []).slice(0, 2);
  for (const url of ghsaPoc) lines.push(`- GHSA-listed: ${url}`);
  const top = record.poc_in_github?.top?.[0];
  if (top?.html_url && !ghsaPoc.includes(top.html_url)) {
    lines.push(`- Highest-star PoC-in-GitHub repository (unvetted; not executed): ${top.html_url}`);
  }
  if (record.poc_in_github?.index_url && record.poc_in_github?.status === 200) {
    lines.push(`- Additional repos indexed by PoC-in-GitHub for this id (unvetted): ${record.poc_in_github.index_url}`);
  }
  for (const url of (record.nvd?.exploitRefs || []).slice(0, 2)) {
    if (!lines.some((line) => line.includes(url))) lines.push(`- NVD Exploit-tagged reference: ${url}`);
  }
  if (record.h1?.url) lines.push(`- Local HackerOne harvest: ${record.h1.url}`);
  return lines;
}

function missingBullets(record) {
  if (record.repro === "verified-public") return ["- (none for verified-public)"];
  const lines = [];
  if (/rejected|disputed/i.test(record.nvd?.vulnStatus || "")) {
    lines.push(`- NVD vulnStatus is ${record.nvd.vulnStatus}.`);
  }
  if (record.ghsa?.withdrawn_at) lines.push(`- GHSA withdrawn_at is ${record.ghsa.withdrawn_at}.`);
  if (record.nvd?.rateLimited) lines.push("- NVD rate-limited; retry next run.");
  if (record.nvd?.totalResults === 0) lines.push("- CVE not in NVD.");
  if (!listPocUrls(record).length) {
    lines.push("- No public PoC (ExploitDB / PoC-in-GitHub / NVD Exploit-tagged refs / GHSA PoC refs empty).");
  } else if (record.repro !== "verified-public") {
    lines.push("- A public link exists, but the advisory prose was not enough to fill a verified reproduction. The link is listed and its body was not copied.");
  }
  if (!firstConcreteInput(record)) {
    lines.push("- No concrete request or payload in the cited advisories. None was invented.");
  }
  if (record.vendor?.status && record.vendor.status !== 200) {
    lines.push("- Vendor advisory was missing, gated, or not fetched.");
  }
  if (!lines.length) lines.push("- Needs lab setup or private disclosure details that are not public.");
  return lines;
}

export function renderSteps(record) {
  const status = record.repro === "unverified"
    ? "> Status: `repro: unverified` — no public, actionable reproduction was found. Nothing below was invented."
    : `> Status: \`repro: ${record.repro}\` — every line below is backed by a cited reference. Nothing here was invented.`;
  const lines = [
    status,
    "",
    "### Prerequisites",
    ...prerequisiteBullets(record),
    "",
    "### Input / trigger",
    inputBullet(record),
    "",
    "### Expected (patched) vs vulnerable behavior",
    expectedBullet(record),
    "",
    "### How to confirm",
    confirmBullet(record),
    "",
    "### Public PoC (if any)",
    ...(publicPocLines(record).length ? publicPocLines(record) : ["- None found."]),
    "",
    "### What's missing",
    ...missingBullets(record),
  ];
  return `${lines.join("\n")}\n`;
}

function sectionBodies(markdown) {
  const parts = String(markdown || "").split(/^## Steps to reproduce\b.*$/m);
  return parts.slice(1);
}

function sectionText(block, heading) {
  const marker = `### ${heading}`;
  const start = block.indexOf(marker);
  if (start < 0) return null;
  const after = block.slice(start + marker.length);
  const next = after.search(/\n### /);
  return next < 0 ? after : after.slice(0, next);
}

export function assertCited(markdown) {
  const blocks = sectionBodies(markdown);
  if (!blocks.length) throw new Error("missing ## Steps to reproduce");
  const required = [
    "Prerequisites",
    "Input / trigger",
    "Expected (patched) vs vulnerable behavior",
    "How to confirm",
  ];
  for (const block of blocks) {
    for (const name of required) {
      const body = sectionText(block, name);
      if (body == null) throw new Error(`missing section ${name}`);
      const bullets = body.split("\n").map((line) => line.trimEnd()).filter((line) => line.startsWith("- "));
      if (!bullets.length) throw new Error(`no bullets in ${name}`);
      for (const line of bullets) {
        if (!/\[\[[^\]]+\]\(https?:\/\/[^)\s]+\)\]\s*$/.test(line)) {
          throw new Error(`uncited line: ${line}`);
        }
      }
    }
  }
  return true;
}

export function assertNoInventedPayload(markdown, corpus) {
  const text = String(markdown || "");
  const source = String(corpus || "");
  for (const pattern of BANNED) {
    if (pattern.test(text)) throw new Error(`banned construct in steps: ${pattern}`);
  }
  for (const token of findAllJndi(text)) {
    if (!source.includes(token)) throw new Error(`uncited payload: ${token}`);
  }
  return true;
}

export function corpusOf(record) {
  return [
    record.nvd?.description,
    record.ghsa?.description,
    record.ghsa?.summary,
    record.vendor?.excerpt,
    record.h1?.excerpt,
  ].filter(Boolean).join("\n");
}

function headingFor(record, citedCves, multiple) {
  if (!multiple) return "## Steps to reproduce";
  const ghsas = (record.cited_as || []).filter((id) => id.toLowerCase().startsWith("ghsa-"));
  if (ghsas.length && !citedCves.has(record.id) && !ghsas.includes(record.id)) {
    return `## Steps to reproduce — ${ghsas.join(", ")} (${record.id})`;
  }
  return `## Steps to reproduce — ${record.id}`;
}

export function renderSkillSteps(records, citedCves) {
  const multiple = records.length > 1;
  return records.map((record) => {
    const body = record.section_markdown || renderSteps(record);
    return `${headingFor(record, citedCves, multiple)}\n\n${body.trim()}\n`;
  }).join("\n");
}

function yamlString(value) {
  if (value == null) return "null";
  return JSON.stringify(String(value));
}

export function buildReferences(record) {
  const refs = [];
  const nvd = record.nvd || {};
  refs.push({
    source: "nvd",
    url: nvd.queryUrl || null,
    gave: nvd.gave || "no NVD record",
  });
  if (record.vendor?.url) {
    refs.push({ source: "vendor", url: record.vendor.url, gave: record.vendor.gave || "vendor advisory URL" });
  }
  const ghsa = record.ghsa || {};
  refs.push({
    source: "ghsa",
    url: ghsa.html_url || null,
    gave: ghsa.gave || "no GHSA for this CVE",
  });
  const kev = record.kev || {};
  refs.push({
    source: "cisa-kev",
    url: kev.url || KEV_URL,
    gave: kev.gave || "not in KEV",
  });
  const edb = record.exploitdb?.[0];
  refs.push({
    source: "exploitdb",
    url: edb?.url || null,
    gave: edb ? `public PoC (EDB-${edb.id})` : (record.exploitdbError || "no row with this CVE in codes"),
  });
  const poc = record.poc_in_github || {};
  const top = poc.top?.[0];
  refs.push({
    source: "poc-in-github",
    url: top?.html_url || null,
    gave: top ? "public PoC repository" : (poc.gave || "no PoC-in-GitHub index"),
  });
  if (record.h1?.url) refs.push({ source: "h1", url: record.h1.url, gave: "local HackerOne harvest links this id" });
  return refs;
}

export function enrichmentYaml(records, citedGhsas) {
  const cveIds = records.map((record) => record.id).filter((id) => id.startsWith("CVE-"));
  const lines = [FM_START];
  if (cveIds.length === 1) lines.push(`cve: ${cveIds[0]}`);
  else if (cveIds.length === 0) lines.push("cve: null");
  else {
    lines.push("cve:");
    for (const id of cveIds) lines.push(`  - ${id}`);
  }
  if (citedGhsas.length === 1) lines.push(`ghsa: ${citedGhsas[0]}`);
  else if (citedGhsas.length > 1) {
    lines.push("ghsa:");
    for (const id of citedGhsas) lines.push(`  - ${id}`);
  }
  lines.push(`repro: ${rollupRepro(records.map((record) => record.repro))}`);
  lines.push("references:");
  const multi = records.length > 1;
  for (const record of records) {
    for (const ref of buildReferences(record)) {
      lines.push(`  - source: ${ref.source}`);
      if (multi) lines.push(`    id: ${record.id}`);
      lines.push(`    url: ${yamlString(ref.url)}`);
      lines.push(`    gave: ${yamlString(ref.gave)}`);
    }
  }
  lines.push(FM_END);
  return lines.join("\n");
}

function locateFrontmatter(text) {
  const lines = text.split("\n");
  let i = 0;
  while (i < lines.length && (lines[i].trim() === "" || lines[i].startsWith("<!--"))) i += 1;
  if (lines[i] !== "---") return null;
  for (let j = i + 1; j < lines.length; j += 1) {
    if (lines[j] === "---") return { start: i, end: j, lines };
  }
  return null;
}

function insertFrontmatter(text, block) {
  const found = locateFrontmatter(text);
  if (!found) {
    return `---\n${block}\n---\n\n${text.replace(/^\n+/, "")}`;
  }
  const { lines, start, end } = found;
  const current = lines.slice(start + 1, end).join("\n");
  let nextInner;
  const marker = current.indexOf(FM_START);
  if (marker >= 0) {
    const finish = current.indexOf(FM_END);
    if (finish < 0) throw new Error("frontmatter enrichment start without end");
    nextInner = `${current.slice(0, marker)}${block}${current.slice(finish + FM_END.length)}`.replace(/\n{3,}/g, "\n\n");
  } else {
    nextInner = `${current.replace(/\s+$/, "")}\n${block}`;
  }
  lines.splice(start + 1, end - start - 1, ...nextInner.split("\n"));
  return lines.join("\n");
}

function insertBody(text, steps) {
  const block = `${BODY_START}\n${steps.trim()}\n${BODY_END}\n`;
  const start = text.indexOf(BODY_START);
  if (start >= 0) {
    const end = text.indexOf(BODY_END, start);
    if (end < 0) throw new Error("steps start without end");
    return `${text.slice(0, start)}${block}${text.slice(end + BODY_END.length).replace(/^\n*/, "")}`;
  }
  return `${text.replace(/\s*$/, "")}\n\n${block}`;
}

export function applyEnrichment(text, records, citedCves, citedGhsas) {
  for (const record of records) {
    record.section_markdown = renderSteps(record);
    assertCited(`## Steps to reproduce\n\n${record.section_markdown}`);
    assertNoInventedPayload(record.section_markdown, corpusOf(record));
    if ((record.repro === "partial" || record.repro === "unverified") && !record.section_markdown.includes("### What's missing")) {
      throw new Error(`missing What's missing for ${record.id}`);
    }
  }
  const steps = renderSkillSteps(records, citedCves);
  assertCited(steps);
  const yaml = enrichmentYaml(records, citedGhsas);
  return insertBody(insertFrontmatter(text, yaml), steps);
}

export function reclassifyChecklist(text) {
  const found = locateFrontmatter(text);
  if (!found) {
    return `---\nkind: checklist\nrepro: checklist\n---\n\n${text.replace(/^\n+/, "")}`;
  }
  const { lines, start, end } = found;
  const inner = lines.slice(start + 1, end);
  const kept = inner.filter((line) => !/^(kind|repro):\s*/.test(line));
  while (kept.length && kept[kept.length - 1].trim() === "") kept.pop();
  kept.push("kind: checklist", "repro: checklist");
  const next = [...lines.slice(0, start + 1), ...kept, ...lines.slice(end)];
  return next.join("\n");
}

function splitCpe(criteria) {
  const parts = [];
  let current = "";
  for (let i = 0; i < criteria.length; i += 1) {
    const ch = criteria[i];
    if (ch === "\\" && i + 1 < criteria.length) {
      current += criteria[i + 1];
      i += 1;
    } else if (ch === ":") {
      parts.push(current);
      current = "";
    } else current += ch;
  }
  parts.push(current);
  return parts;
}

function rangeFromMatch(match) {
  const bits = [];
  if (match.versionStartIncluding) bits.push(`>= ${match.versionStartIncluding}`);
  if (match.versionStartExcluding) bits.push(`> ${match.versionStartExcluding}`);
  if (match.versionEndIncluding) bits.push(`<= ${match.versionEndIncluding}`);
  if (match.versionEndExcluding) bits.push(`< ${match.versionEndExcluding}`);
  const version = match.criteria ? splitCpe(match.criteria)[5] : "";
  if (!bits.length && version && version !== "*" && version !== "-") bits.push(version);
  return bits.join(", ");
}

function walkCpe(nodes, found) {
  for (const node of nodes || []) {
    for (const match of node.cpeMatch || node.cpe_match || []) {
      if (match.vulnerable === false) continue;
      const parts = splitCpe(match.criteria || "");
      found.push({
        vendor: (parts[3] || "").replace(/\\/g, ""),
        product: (parts[4] || "").replace(/\\/g, ""),
        range: rangeFromMatch(match),
      });
    }
    walkCpe(node.children || [], found);
  }
}

export function summarizeNvd(payload, cve) {
  const queryUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}`;
  const detailUrl = `https://nvd.nist.gov/vuln/detail/${cve}`;
  const total = payload?.totalResults ?? 0;
  const cveObj = payload?.vulnerabilities?.[0]?.cve;
  if (!cveObj || total === 0) {
    return {
      status: 200,
      queryUrl,
      detailUrl,
      totalResults: 0,
      description: "",
      products: [],
      productCount: 0,
      exploitRefs: [],
      vendorRefs: [],
      cwes: [],
      gave: "CVE not in NVD",
    };
  }
  const description = (cveObj.descriptions || []).find((item) => item.lang === "en")?.value
    || cveObj.descriptions?.[0]?.value
    || "";
  const products = [];
  for (const config of cveObj.configurations || []) walkCpe(config.nodes || [], products);
  const deduped = [];
  const seen = new Set();
  for (const product of products) {
    const key = `${product.vendor}|${product.product}|${product.range}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(product);
  }
  const references = (cveObj.references || []).filter((ref) => !(ref.tags || []).includes("Broken Link"));
  const exploitRefs = references.filter((ref) => (ref.tags || []).includes("Exploit")).map((ref) => ref.url).filter(Boolean);
  const vendorRefs = [];
  for (const tag of ["Vendor Advisory", "Patch", "Mitigation"]) {
    for (const ref of references) {
      if ((ref.tags || []).includes(tag) && ref.url) vendorRefs.push({ url: ref.url, tags: ref.tags });
    }
  }
  const cwes = [];
  for (const weakness of cveObj.weaknesses || []) {
    for (const desc of weakness.description || []) {
      if (desc.value && desc.value !== "NVD-CWE-noinfo" && desc.value !== "NVD-CWE-Other") cwes.push(desc.value);
    }
  }
  const metric = cveObj.metrics?.cvssMetricV31?.[0] || cveObj.metrics?.cvssMetricV30?.[0] || null;
  const gave = exploitRefs.length
    ? `descriptions, configurations, ${exploitRefs.length} Exploit-tagged refs`
    : "description, configurations; no Exploit-tagged refs";
  return {
    status: 200,
    queryUrl,
    detailUrl,
    totalResults: total,
    vulnStatus: cveObj.vulnStatus || "",
    description,
    products: deduped.slice(0, 12),
    productCount: deduped.length,
    exploitRefs: [...new Set(exploitRefs)].slice(0, 20),
    vendorRefs,
    cwes: [...new Set(cwes)].slice(0, 6),
    cvss: metric ? { score: metric.cvssData?.baseScore, severity: metric.cvssData?.baseSeverity } : null,
    gave,
  };
}

function versionPhrase(text) {
  const match = String(text || "").match(/\b\d+\.\d+(?:\.\d+){0,2}(?:-beta\d+|-rc\d+)?\s+(?:through|to|before)\s+\d+\.\d+(?:\.\d+){0,2}(?:-beta\d+|-rc\d+)?\b/i);
  if (!match) return "";
  const phrase = match[0];
  if (phrase.length > 80 || /[<>[\]]/.test(phrase)) return "";
  return phrase;
}

export function htmlToText(html) {
  return String(html || "")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&#36;/g, "$")
    .replace(/\s+/g, " ")
    .trim();
}

export function summarizeVendor(url, status, html) {
  if (status !== 200 || !html) {
    return { url, status: status || 0, excerpt: "", versionPhrases: [], gave: `broken or gated (${status || "error"})` };
  }
  const text = htmlToText(html).replace(/\u0000/g, "");
  const excerpt = text.slice(0, 400);
  const phrase = versionPhrase(text.slice(0, 4000));
  return {
    url,
    status,
    excerpt,
    excerpt_sha256: sha256(excerpt),
    versionPhrases: phrase ? [phrase] : [],
    gave: phrase ? "affected range phrase plus advisory URL" : "advisory page fetched; no concrete input copied",
  };
}

function ghsaPocRefs(references, sourceCode) {
  const urls = [];
  for (const ref of references || []) {
    const url = typeof ref === "string" ? ref : ref?.url;
    if (!url || url === sourceCode) continue;
    let host = "";
    try { host = new URL(url).hostname.toLowerCase(); } catch { continue; }
    if (["nvd.nist.gov", "services.nvd.nist.gov", "cve.mitre.org", "www.cve.org", "cve.mitre.org"].includes(host)) continue;
    if (host === "github.com" && /\/advisories\//.test(url)) continue;
    if (host === "github.com") {
      if (/poc|exploit/i.test(url)) urls.push(url);
      continue;
    }
    if (/poc|exploit/i.test(url)) urls.push(url);
  }
  return [...new Set(urls)].slice(0, 10);
}

function versionString(value) {
  if (!value) return "";
  if (typeof value === "string") return value;
  if (typeof value === "object") return value.identifier || value.version || "";
  return String(value);
}

function mapPackages(list) {
  return (list || []).slice(0, 6).map((item) => ({
    ecosystem: item.package?.ecosystem || item.ecosystem || "",
    name: item.package?.name || item.name || "",
    range: item.vulnerable_version_range || item.range || "",
    patched: versionString(item.first_patched_version || item.patched),
  })).filter((item) => item.name);
}

export function summarizeGhsa(advisory) {
  if (!advisory) {
    return { status: 0, html_url: null, packages: [], pocRefs: [], gave: "no GHSA for this CVE" };
  }
  const packages = mapPackages(advisory.vulnerabilities || advisory.packages);
  const references = advisory.references || [];
  const pocRefs = ghsaPocRefs(references, advisory.source_code_location);
  const html = advisory.html_url || (advisory.ghsa_id ? `https://github.com/advisories/${advisory.ghsa_id}` : null);
  let gave = packages.length
    ? "package range, first_patched_version, references"
    : "advisory text; no package range";
  if (advisory.withdrawn_at) gave = `withdrawn at ${advisory.withdrawn_at}`;
  if (advisory.via) gave = `${gave} (via ${advisory.via})`;
  return {
    status: 200,
    ghsa_id: advisory.ghsa_id || advisory.id || "",
    html_url: html,
    summary: advisory.summary || "",
    description: advisory.description || advisory.details || "",
    withdrawn_at: advisory.withdrawn_at || advisory.withdrawn || null,
    packages,
    pocRefs,
    via: advisory.via || "",
    gave,
  };
}

export function summarizeOsv(payload) {
  if (!payload || !payload.id) return null;
  const packages = [];
  for (const affected of payload.affected || []) {
    const events = (affected.ranges || []).flatMap((range) => range.events || []);
    const introduced = events.find((event) => event.introduced && event.introduced !== "0")?.introduced;
    const fixed = events.find((event) => event.fixed)?.fixed;
    const range = [introduced ? `>= ${introduced}` : "", fixed ? `< ${fixed}` : ""].filter(Boolean).join(", ");
    packages.push({
      package: { ecosystem: affected.package?.ecosystem, name: affected.package?.name },
      vulnerable_version_range: range,
      first_patched_version: fixed || "",
    });
  }
  return summarizeGhsa({
    ghsa_id: String(payload.id).startsWith("GHSA-") ? payload.id : (payload.aliases || []).find((id) => String(id).startsWith("GHSA-")) || "",
    summary: payload.summary || "",
    description: payload.details || "",
    withdrawn_at: payload.withdrawn || null,
    references: payload.references || [],
    vulnerabilities: packages,
    via: "osv",
  });
}

export function lookupKev(catalog, cve) {
  if (!catalog) {
    return { in_kev: null, url: KEV_URL, gave: "KEV feed unavailable; exploited_in_wild unset" };
  }
  const hit = catalog.get(cve);
  if (!hit) return { in_kev: false, url: KEV_URL, gave: "not in KEV" };
  return {
    in_kev: true,
    url: KEV_URL,
    dateAdded: hit.dateAdded || "",
    dueDate: hit.dueDate || "",
    knownRansomwareCampaignUse: hit.knownRansomwareCampaignUse || "",
    gave: `dateAdded ${hit.dateAdded || "unknown"}, dueDate ${hit.dueDate || "unknown"}, knownRansomwareCampaignUse=${hit.knownRansomwareCampaignUse || "unknown"}`,
  };
}

export function parseCsv(text) {
  const rows = [];
  let row = [];
  let cell = "";
  let quoted = false;
  const source = String(text || "");
  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i];
    if (quoted) {
      if (ch === '"') {
        if (source[i + 1] === '"') {
          cell += '"';
          i += 1;
        } else quoted = false;
      } else cell += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      row.push(cell);
      cell = "";
    } else if (ch === "\n") {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
    } else if (ch !== "\r") cell += ch;
  }
  if (cell.length || row.length) {
    row.push(cell);
    rows.push(row);
  }
  return rows.filter((item) => item.some((value) => value !== ""));
}

export function indexExploitdb(csvText) {
  const table = parseCsv(csvText);
  if (!table.length) return new Map();
  const header = table[0].map((name) => name.trim());
  const col = (name) => header.indexOf(name);
  const idCol = col("id");
  const fileCol = col("file");
  const codesCol = col("codes");
  const verifiedCol = col("verified");
  const map = new Map();
  if (idCol < 0 || fileCol < 0 || codesCol < 0) return map;
  for (const record of table.slice(1)) {
    const codes = String(record[codesCol] || "").split(/[;,]/).map((item) => item.trim().toUpperCase()).filter(Boolean);
    if (!codes.length) continue;
    const entry = {
      id: record[idCol],
      file: record[fileCol],
      verified: String(record[verifiedCol] || "") === "1" ? 1 : 0,
      url: `https://gitlab.com/exploit-database/exploitdb/-/blob/main/${record[fileCol]}`,
    };
    for (const code of codes) {
      if (!map.has(code)) map.set(code, []);
      const list = map.get(code);
      if (list.length < 5) list.push(entry);
    }
  }
  return map;
}

export function indexKev(payload) {
  const map = new Map();
  for (const item of payload?.vulnerabilities || []) {
    if (item?.cveID) map.set(String(item.cveID).toUpperCase(), item);
  }
  return map;
}

function vendorFetchable(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return false;
    if (VENDOR_SKIP_HOSTS.has(parsed.hostname.toLowerCase())) return false;
    if (/\.(pdf|zip|gz|tgz|patch|diff|exe|msi|xz)(\?|$)/i.test(parsed.pathname)) return false;
    return true;
  } catch {
    return false;
  }
}

function pickVendorUrl(refs) {
  for (const ref of refs || []) {
    if (vendorFetchable(ref.url)) return ref.url;
  }
  return "";
}

async function readBody(res, maxBytes) {
  const length = Number(res.headers?.get?.("content-length") || 0);
  if (length && length > maxBytes) throw new Error(`response exceeded ${maxBytes} bytes`);
  const text = await res.text();
  if (text.length > maxBytes) throw new Error(`response exceeded ${maxBytes} bytes`);
  return text;
}

async function request(ctx, url, { headers = {}, timeoutMs = 20000, maxBytes = 2_000_000 } = {}) {
  const fetchImpl = ctx.fetch || globalThis.fetch;
  let lastError = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetchImpl(url, {
        headers: { "user-agent": USER_AGENT, accept: "*/*", ...headers },
        redirect: "follow",
        signal: controller.signal,
      });
      const body = await readBody(res, maxBytes);
      if (attempt === 0 && res.status >= 500) {
        lastError = new Error(`status ${res.status}`);
        await ctx.sleep(2000);
        continue;
      }
      return { status: res.status, body, headers: res.headers };
    } catch (error) {
      lastError = error;
      if (attempt === 0) await ctx.sleep(2000);
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastError || new Error(`request failed ${url}`);
}

async function pauseForNvd(ctx) {
  const wait = nvdWaitMs(ctx.lastNvdAt, Date.now(), ctx.nvdIntervalMs);
  if (wait > 0) await ctx.sleep(wait);
}

function githubToken(ctx) {
  if (ctx.token != null) return ctx.token;
  if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN;
  if (process.env.GH_TOKEN) return process.env.GH_TOKEN;
  try {
    return execFileSync("gh", ["auth", "token"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return "";
  }
}

function githubHeaders(ctx) {
  const headers = {
    accept: "application/vnd.github+json",
    "x-github-api-version": "2022-11-28",
  };
  const token = githubToken(ctx);
  if (token) headers.authorization = `Bearer ${token}`;
  return headers;
}

export function createRunContext(opts = {}) {
  return {
    fetch: opts.fetch,
    sleep: opts.sleep || ((ms) => new Promise((resolve) => setTimeout(resolve, ms))),
    nvdIntervalMs: opts.nvdIntervalMs ?? NVD_MIN_INTERVAL_MS,
    lastNvdAt: 0,
    token: opts.token,
    cacheDir: opts.cacheDir || join(ROOT, "skills/_index/repro"),
    kev: opts.kev || null,
    exploitdb: opts.exploitdb || null,
    exploitdbError: opts.exploitdbError || "",
    h1ByCve: opts.h1ByCve || new Map(),
    vendorHosts: new Set(),
    force: Boolean(opts.force),
    maxAgeMs: opts.maxAgeMs ?? CACHE_FRESH_MS,
    now: opts.now || (() => new Date()),
    githubBlocked: false,
    log: opts.log || (() => {}),
  };
}

function cachePath(ctx, id) {
  return join(ctx.cacheDir, `${id}.json`);
}

async function readFreshCache(ctx, id) {
  if (ctx.force) return null;
  const path = cachePath(ctx, id);
  if (!existsSync(path)) return null;
  try {
    const parsed = JSON.parse(await readFile(path, "utf8"));
    const fetched = Date.parse(parsed.fetched_at || "");
    if (!Number.isFinite(fetched)) return null;
    if (ctx.now().getTime() - fetched > ctx.maxAgeMs) return null;
    return parsed.record || null;
  } catch {
    return null;
  }
}

export function cacheDocument(record) {
  const excerpts = [];
  if (record.nvd?.description) excerpts.push({ source: "nvd", sha256: sha256(record.nvd.description), text: record.nvd.description.slice(0, 500) });
  if (record.vendor?.excerpt) excerpts.push({ source: "vendor", sha256: record.vendor.excerpt_sha256 || sha256(record.vendor.excerpt), text: record.vendor.excerpt.slice(0, 400) });
  if (record.ghsa?.description) excerpts.push({ source: "ghsa", sha256: sha256(record.ghsa.description), text: record.ghsa.description.slice(0, 500) });
  return {
    cve: record.id.startsWith("CVE-") ? record.id : null,
    id: record.id,
    fetched_at: record.fetched_at,
    repro: record.repro,
    sources: {
      nvd: {
        status: record.nvd?.status ?? null,
        url: record.nvd?.queryUrl || null,
        vulnStatus: record.nvd?.vulnStatus || "",
        exploit_refs: record.nvd?.exploitRefs || [],
        rateLimited: Boolean(record.nvd?.rateLimited),
      },
      vendor: record.vendor?.url ? [{ url: record.vendor.url, status: record.vendor.status }] : [],
      ghsa: record.ghsa?.ghsa_id
        ? { status: record.ghsa.status, ghsa_id: record.ghsa.ghsa_id, html_url: record.ghsa.html_url, via: record.ghsa.via || "" }
        : null,
      kev: {
        in_kev: record.kev?.in_kev ?? null,
        dateAdded: record.kev?.dateAdded || "",
        knownRansomwareCampaignUse: record.kev?.knownRansomwareCampaignUse || "",
      },
      exploitdb: (record.exploitdb || []).map((row) => ({ id: row.id, file: row.file, verified: row.verified })),
      poc_in_github: (record.poc_in_github?.top || []).map((row) => ({ html_url: row.html_url, stargazers_count: row.stargazers_count || 0 })),
    },
    references: buildReferences(record),
    section_markdown: record.section_markdown || "",
    audit: { excerpts },
    record,
  };
}

async function writeCache(ctx, record) {
  if (!ctx.cacheDir || ctx.dryRun) return;
  await mkdir(ctx.cacheDir, { recursive: true });
  const path = cachePath(ctx, record.id);
  const tmp = `${path}.${process.pid}.tmp`;
  await writeFile(tmp, `${JSON.stringify(cacheDocument(record), null, 2)}\n`);
  await rename(tmp, path);
}

function emptyNvd(cve, extra = {}) {
  return {
    status: extra.status ?? 0,
    queryUrl: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}`,
    detailUrl: `https://nvd.nist.gov/vuln/detail/${cve}`,
    totalResults: extra.totalResults ?? null,
    description: "",
    products: [],
    productCount: 0,
    exploitRefs: [],
    vendorRefs: [],
    cwes: [],
    gave: extra.gave || "NVD request failed",
    rateLimited: Boolean(extra.rateLimited),
    error: extra.error || "",
  };
}

async function fetchNvd(ctx, cve) {
  await pauseForNvd(ctx);
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}`;
  const headers = {};
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY;
  try {
    let response = await request(ctx, url, { headers, timeoutMs: 30000, maxBytes: 3_000_000 });
    ctx.lastNvdAt = Date.now();
    if (response.status === 403 || response.status === 429) {
      await ctx.sleep(Math.max(ctx.nvdIntervalMs, 30000));
      response = await request(ctx, url, { headers, timeoutMs: 30000, maxBytes: 3_000_000 });
      ctx.lastNvdAt = Date.now();
    }
    if (response.status === 403 || response.status === 429) {
      return emptyNvd(cve, { status: response.status, rateLimited: true, gave: "NVD rate-limited; retry next run" });
    }
    if (response.status !== 200) return emptyNvd(cve, { status: response.status, gave: `NVD status ${response.status}` });
    return summarizeNvd(JSON.parse(response.body), cve);
  } catch (error) {
    ctx.lastNvdAt = Date.now();
    return emptyNvd(cve, { gave: "NVD request failed", error: error.message });
  }
}

async function fetchVendor(ctx, nvd) {
  const url = pickVendorUrl(nvd?.vendorRefs);
  if (!url) return null;
  let host = "";
  try { host = new URL(url).hostname.toLowerCase(); } catch { return null; }
  if (ctx.vendorHosts.has(host)) {
    return { url, status: 0, excerpt: "", versionPhrases: [], gave: "not fetched; one request per host per run" };
  }
  ctx.vendorHosts.add(host);
  try {
    const response = await request(ctx, url, { timeoutMs: 12000, maxBytes: 500_000 });
    return summarizeVendor(url, response.status, response.status === 200 ? response.body : "");
  } catch (error) {
    return { url, status: 0, excerpt: "", versionPhrases: [], gave: `vendor fetch failed: ${error.message}` };
  }
}

async function fetchGhsaByCve(ctx, cve) {
  if (ctx.githubBlocked) return fetchOsv(ctx, cve);
  const url = `https://api.github.com/advisories?cve_id=${encodeURIComponent(cve)}&per_page=5`;
  try {
    const response = await request(ctx, url, { headers: githubHeaders(ctx), timeoutMs: 20000, maxBytes: 2_000_000 });
    const remaining = response.headers?.get?.("x-ratelimit-remaining");
    if (remaining === "0") ctx.githubBlocked = true;
    if (response.status === 403 || response.status === 429) {
      ctx.githubBlocked = true;
      return fetchOsv(ctx, cve);
    }
    if (response.status !== 200) return { ...summarizeGhsa(null), gave: `GHSA status ${response.status}` };
    const list = JSON.parse(response.body);
    const advisory = (Array.isArray(list) ? list : []).find((item) => !item.withdrawn_at) || (Array.isArray(list) ? list[0] : null);
    return summarizeGhsa(advisory);
  } catch (error) {
    return { ...summarizeGhsa(null), gave: `GHSA request failed: ${error.message}` };
  }
}

async function fetchGhsaById(ctx, ghsaId) {
  const url = `https://api.github.com/advisories/${ghsaId}`;
  try {
    const response = await request(ctx, url, { headers: githubHeaders(ctx), timeoutMs: 20000, maxBytes: 1_000_000 });
    if (response.status === 403 || response.status === 429) {
      ctx.githubBlocked = true;
      return null;
    }
    if (response.status !== 200) return null;
    return JSON.parse(response.body);
  } catch {
    return null;
  }
}

async function fetchOsv(ctx, id) {
  try {
    const response = await request(ctx, `https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { timeoutMs: 20000, maxBytes: 2_000_000 });
    if (response.status !== 200) return { ...summarizeGhsa(null), gave: "no GHSA for this CVE" };
    return summarizeOsv(JSON.parse(response.body)) || { ...summarizeGhsa(null), gave: "no GHSA for this CVE" };
  } catch {
    return { ...summarizeGhsa(null), gave: "GitHub rate-limited; OSV lookup failed" };
  }
}

async function fetchPoc(ctx, cve) {
  const year = cve.slice(4, 8);
  const indexUrl = `https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/${year}/${cve}.json`;
  try {
    const response = await request(ctx, indexUrl, { timeoutMs: 20000, maxBytes: 8_000_000 });
    if (response.status === 404) return { status: 404, index_url: indexUrl, top: [], gave: `404 for master/${year}/${cve}.json` };
    if (response.status !== 200) return { status: response.status, index_url: indexUrl, top: [], gave: `PoC-in-GitHub status ${response.status}` };
    const parsed = JSON.parse(response.body);
    const list = Array.isArray(parsed) ? parsed : [];
    const top = list
      .filter((item) => item?.html_url)
      .sort((a, b) => (b.stargazers_count || 0) - (a.stargazers_count || 0) || String(b.pushed_at || "").localeCompare(String(a.pushed_at || "")))
      .slice(0, 3)
      .map((item) => ({
        html_url: item.html_url,
        stargazers_count: item.stargazers_count || 0,
        description: String(item.description || "").slice(0, 120),
      }));
    return { status: 200, index_url: indexUrl, count: list.length, top, gave: top.length ? "public PoC repository" : "index empty" };
  } catch (error) {
    return { status: 0, index_url: indexUrl, top: [], gave: `PoC-in-GitHub failed: ${error.message}` };
  }
}

function attachDerived(record) {
  record.repro = classifyRecord(record);
  record.section_markdown = renderSteps(record);
  return record;
}

export async function enrichCve(cve, ctx, extras = {}) {
  const id = String(cve).toUpperCase();
  const cached = await readFreshCache(ctx, id);
  if (cached?.repro && (cached.nvd || cached.ghsa)) {
    cached.repro = classifyRecord(cached);
    cached.section_markdown = renderSteps(cached);
    await writeCache(ctx, cached);
    return cached;
  }
  const nvd = await fetchNvd(ctx, id);
  const vendor = await fetchVendor(ctx, nvd);
  const ghsa = extras.preloadedGhsa ? summarizeGhsa(extras.preloadedGhsa) : await fetchGhsaByCve(ctx, id);
  const kev = lookupKev(ctx.kev, id);
  const exploitdb = ctx.exploitdb ? (ctx.exploitdb.get(id) || []) : [];
  const poc = await fetchPoc(ctx, id);
  const h1 = ctx.h1ByCve.get(id) || null;
  const record = attachDerived({
    id,
    fetched_at: ctx.now().toISOString(),
    nvd,
    vendor,
    ghsa,
    kev,
    exploitdb,
    exploitdbError: ctx.exploitdb ? "" : (ctx.exploitdbError || "ExploitDB CSV unavailable"),
    poc_in_github: poc,
    h1,
    cited_as: [],
  });
  await writeCache(ctx, record);
  ctx.log(`${id} ${record.repro}`);
  return record;
}

export async function enrichGhsa(ghsaId, ctx) {
  const id = String(ghsaId).toLowerCase();
  const cachedOnly = await readFreshCache(ctx, id);
  if (cachedOnly?.repro && cachedOnly.ghsa && !String(cachedOnly.id).startsWith("CVE-")) {
    cachedOnly.repro = classifyRecord(cachedOnly);
    cachedOnly.section_markdown = renderSteps(cachedOnly);
    await writeCache(ctx, cachedOnly);
    return cachedOnly;
  }
  const advisory = await fetchGhsaById(ctx, id);
  const cve = advisory?.cve_id ? String(advisory.cve_id).toUpperCase() : "";
  if (cve) {
    const record = await enrichCve(cve, ctx, { preloadedGhsa: advisory });
    if (!record.cited_as.includes(id)) record.cited_as.push(id);
    return record;
  }
  const ghsa = advisory
    ? summarizeGhsa(advisory)
    : await fetchOsv(ctx, id);
  const record = attachDerived({
    id,
    fetched_at: ctx.now().toISOString(),
    nvd: {
      status: null,
      queryUrl: null,
      detailUrl: null,
      description: "",
      products: [],
      exploitRefs: [],
      gave: "no CVE id on this advisory; NVD not queried",
    },
    vendor: null,
    ghsa: ghsa.ghsa_id ? ghsa : { ...ghsa, ghsa_id: id, html_url: `https://github.com/advisories/${id}`, gave: ghsa.gave || "GHSA lookup failed" },
    kev: { in_kev: null, url: KEV_URL, gave: "no CVE id; KEV not applicable" },
    exploitdb: [],
    exploitdbError: "no CVE id; ExploitDB not queried",
    poc_in_github: { status: 0, top: [], gave: "no CVE id; PoC-in-GitHub not queried" },
    h1: null,
    cited_as: [id],
  });
  if (!record.ghsa.html_url) record.ghsa.html_url = `https://github.com/advisories/${id}`;
  record.repro = classifyRecord(record);
  record.section_markdown = renderSteps(record);
  await writeCache(ctx, record);
  ctx.log(`${id} ${record.repro}`);
  return record;
}

export async function loadFeeds(ctx) {
  try {
    const response = await request(ctx, KEV_URL, { timeoutMs: 30000, maxBytes: 8_000_000 });
    if (response.status === 200) ctx.kev = indexKev(JSON.parse(response.body));
  } catch (error) {
    ctx.log(`KEV download failed: ${error.message}`);
  }
  try {
    const response = await request(ctx, EDB_CSV_URL, { timeoutMs: 60000, maxBytes: 20_000_000 });
    if (response.status === 200) ctx.exploitdb = indexExploitdb(response.body);
    else ctx.exploitdbError = `ExploitDB CSV status ${response.status}`;
  } catch (error) {
    ctx.exploitdbError = `ExploitDB CSV failed: ${error.message}`;
    ctx.log(ctx.exploitdbError);
  }
}

export async function loadH1Index(reportsDir) {
  const map = new Map();
  let names = [];
  try { names = await readdir(reportsDir); } catch { return map; }
  for (const name of names) {
    if (!/^h1-.*\.json$/.test(name)) continue;
    try {
      const parsed = JSON.parse(await readFile(join(reportsDir, name), "utf8"));
      const info = typeof parsed.vulnerabilityInformation === "string" ? parsed.vulnerabilityInformation : "";
      for (const cve of parsed.cveIds || []) {
        const id = String(cve).toUpperCase();
        if (!/^CVE-\d{4}-\d{4,}$/.test(id)) continue;
        const current = map.get(id);
        const entry = {
          url: parsed.reportUrl || "",
          hasText: info.trim().length >= 40,
          excerpt: info.trim().slice(0, 240),
        };
        if (!current || (entry.hasText && !current.hasText)) map.set(id, entry);
      }
    } catch {
      // skip unreadable harvest files
    }
  }
  return map;
}

export async function enrichSkillText(text, ctx) {
  const { cves, ghsas } = expandCitedIds(stripEnrichment(text));
  const records = [];
  const byId = new Map();
  for (const cve of cves) {
    const record = await enrichCve(cve, ctx);
    if (!byId.has(record.id)) {
      byId.set(record.id, record);
      records.push(record);
    }
  }
  for (const ghsa of ghsas) {
    const record = await enrichGhsa(ghsa, ctx);
    const existing = byId.get(record.id);
    if (existing) {
      if (!existing.cited_as.includes(ghsa)) existing.cited_as.push(ghsa);
      continue;
    }
    if (!record.cited_as.includes(ghsa)) record.cited_as.push(ghsa);
    byId.set(record.id, record);
    records.push(record);
  }
  if (!records.length) throw new Error("no CVE or GHSA ids in skill");
  return { text: applyEnrichment(text, records, new Set(cves), ghsas), records };
}

export function countRepro(records) {
  const counts = { "verified-public": 0, partial: 0, unverified: 0 };
  for (const record of records) counts[record.repro] = (counts[record.repro] || 0) + 1;
  return counts;
}

function argValue(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? "" : process.argv[index + 1] || "";
}

async function main() {
  const dryRun = process.argv.includes("--dry-run");
  const force = process.argv.includes("--force");
  const cacheDir = argValue("--cache-dir") || join(ROOT, "skills/_index/repro");
  const ctx = createRunContext({
    cacheDir,
    force,
    dryRun,
    log: (message) => process.stderr.write(`${message}\n`),
  });
  ctx.dryRun = dryRun;
  if (process.argv.includes("--help")) {
    process.stdout.write("usage: node scripts/enrich-repro.mjs --cve CVE-YYYY-NNNN | --backfill [--dry-run] [--force]\n");
    return;
  }
  if (dryRun && process.argv.includes("--backfill")) {
    const preview = [];
    for (const rel of TIER_A_SKILLS) {
      const text = await readFile(join(ROOT, rel), "utf8");
      preview.push({ skill: rel, ...expandCitedIds(stripEnrichment(text)) });
    }
    process.stdout.write(`${JSON.stringify({ dry_run: true, skills: preview }, null, 2)}\n`);
    return;
  }
  const single = argValue("--cve") || argValue("--ghsa");
  if (!single && !process.argv.includes("--backfill")) {
    process.stderr.write("pass --cve, --ghsa, or --backfill\n");
    process.exitCode = 1;
    return;
  }
  ctx.h1ByCve = await loadH1Index(join(ROOT, "reports"));
  await loadFeeds(ctx);
  const unique = new Map();
  if (single) {
    const record = single.toUpperCase().startsWith("CVE-")
      ? await enrichCve(single.toUpperCase(), ctx)
      : await enrichGhsa(single.toLowerCase(), ctx);
    unique.set(record.id, record);
    process.stdout.write(`${record.section_markdown}`);
  } else {
    for (const rel of TIER_A_SKILLS) {
      const full = join(ROOT, rel);
      const original = await readFile(full, "utf8");
      const { text, records } = await enrichSkillText(original, ctx);
      if (!dryRun) {
        const tmp = `${full}.${process.pid}.tmp`;
        const next = text.endsWith("\n") ? text : `${text}\n`;
        await writeFile(tmp, next);
        await rename(tmp, full);
      }
      for (const record of records) unique.set(record.id, record);
      ctx.log(`updated ${rel}`);
    }
    if (!dryRun) {
      for (const rel of CHECKLIST_SKILLS) {
        const full = join(ROOT, rel);
        const next = reclassifyChecklist(await readFile(full, "utf8"));
        await writeFile(full, next.endsWith("\n") ? next : `${next}\n`);
        ctx.log(`reclassified ${rel}`);
      }
    }
  }
  const counts = countRepro([...unique.values()]);
  const summary = {
    unique_ids: unique.size,
    verified_public: counts["verified-public"] || 0,
    partial: counts.partial || 0,
    unverified: counts.unverified || 0,
    skills: TIER_A_SKILLS.length,
    checklists: CHECKLIST_SKILLS.length,
    cache_dir: cacheDir,
    ids: [...unique.values()].map((record) => ({ id: record.id, repro: record.repro })),
  };
  if (!dryRun && process.argv.includes("--backfill")) {
    await mkdir(cacheDir, { recursive: true });
    await writeFile(join(cacheDir, "SUMMARY.json"), `${JSON.stringify(summary, null, 2)}\n`);
  }
  if (process.argv.includes("--backfill")) process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}
