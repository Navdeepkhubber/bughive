import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, writeFile, mkdir, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { apply as validator } from '../plugins/dsh-finding-validator/index.js';
import { apply as claimAudit, auditClaims } from '../plugins/dsh-claim-audit/index.js';
import { canonicalClass, score } from '../plugins/dsh-eval/index.js';
import { applyPolicy } from '../scripts/pipeline/jev-decide.mjs';
import { apply as fpFilter } from '../plugins/dsh-fp-filter/index.js';

function harness(web) {
  const tools = new Map();
  const ctx = { tools: { register: t => tools.set(t.name, t) }, get: key => key === 'web' ? web : undefined, emit() {} };
  return { ctx, tools };
}

test('generic differential is a lead, never validated proof', async () => {
  const { ctx, tools } = harness({ async fetch({ url }) {
    return { statusCode: url.endsWith('/public') ? 200 : 403, body: { content: url } };
  } });
  validator(ctx);
  const result = JSON.parse(await tools.get('validate_finding').execute({
    baseline: JSON.stringify({ url: 'https://fixture.test/private' }),
    probe: JSON.stringify({ url: 'https://fixture.test/public' }),
  }));
  assert.equal(result.observedDifference, true);
  assert.equal(result.validated, false);
});

test('audit requires the same method and endpoint, and excludes generated reports', async () => {
  const line = JSON.stringify({ kind: 'request', summary: 'GET /api/item -> 200', detail: { method: 'GET', url: 'https://fixture.test/api/item', payload: "' OR 1=1" } });
  const wrongMethod = auditClaims('SQLi was tested on POST /api/item.', line);
  assert.equal(wrongMethod.pass, false);
  assert.equal(wrongMethod.unsupported_count, 1);
  const wrongPath = auditClaims('SQLi was tested on GET /api/items.', line);
  assert.equal(wrongPath.pass, false);
  const unproven = auditClaims('Confirmed SQLi on GET /api/item.', line);
  assert.equal(unproven.pass, false);
  assert.equal(unproven.unverifiable_count, 1);
  const dir = await mkdtemp(join(tmpdir(), 'bh-accuracy-'));
  await writeFile(join(dir, 'SUMMARY.md'), 'SQLi was tested on GET /api/item using an OR payload.');
  await writeFile(join(dir, 'journal.jsonl'), JSON.stringify({ kind: 'request', summary: 'GET /health -> 200' }) + '\n');
  const { ctx, tools } = harness();
  claimAudit(ctx);
  const result = JSON.parse(await tools.get('audit_report').execute({ reportText: 'SQLi was tested on GET /api/item.', evidencePaths: dir }));
  assert.equal(result.pass, false);
});

test('fixture scorer respects exact class, method and route boundaries', async () => {
  const truth = JSON.parse(await readFile(new URL('../plugins/dsh-eval/ground-truth.json', import.meta.url)));
  assert.equal(canonicalClass('idor-write', truth.class_aliases), 'idor-write');
  const perfect = score(truth.bugs.map(b => ({ class: b.class, path: b.path, method: b.method })), truth);
  assert.equal(perfect.tp, truth.bugs.length);
  const bogus = score([
    { class: 'idor', path: '/api/users/2', method: 'POST' },
    { class: 'jwt', path: '/api/administrator', method: 'GET' },
  ], truth);
  assert.equal(bogus.tp, 0);
  assert.equal(bogus.fp, 2);
});

test('planner attempts an evidence-bound hypothesis after recon instead of stopping on hold', () => {
  const skills = [{ id: 'seeds/unauth-api', key: 'seeds__unauth-api', blurb: 'unauthenticated API access' }];
  const snap = {
    done: ['scope', 'skills'], legal: [], recon: {
      '04-http-probe': { count: 1, items: [{ url: 'https://fixture.test/api/users' }] },
    },
    keyword: [{ skill: 'seeds/unauth-api', score: 3 }], hasKeyword: true,
    counts: { hypotheses: 0, hypotheses_pass: 0, hypotheses_real: 0, validated: 0, reports: 0 },
  };
  const routing = { model: 'test', answers: {
    next_action: { choice: 'select_and_test', confidence: 0.64 },
    recon_phase: { choice: 'none' }, skill: { choice: 'seeds__unauth-api', probabilities: { 'seeds__unauth-api': 0.26 } },
    worth_testing: { noul: 0.57 }, human_review: { noul: 0.9 }, signal: { score: 2 },
  } };
  const confirm = { model: 'test', focus: { urls: ['https://fixture.test/api/users'] }, answers: {
    load_0: { noul: 0.1 }, vuln: { choice: 'seeds__unauth-api' },
    test_method: { choice: 'hold', confidence: 0.74 }, focus: { choice: 'u0' },
  } };
  const first = applyPolicy({ snap, skills, routing, confirm });
  assert.equal(first.next_action, 'select_and_test');
  assert.equal(first.test_method, 'checklist_walk');
  assert.equal(first.skills.length, 1);
  const afterAttempt = applyPolicy({ snap: { ...snap, done: [...snap.done, 'hypothesis'] }, skills,
    routing: { ...routing, answers: { ...routing.answers, next_action: { choice: 'stop', confidence: 0.8 } } }, confirm: null });
  assert.notEqual(afterAttempt.next_action, 'select_and_test', 'an empty attempt must not loop forever');
});

test('prefilter accepts a scoped wildcard host and supplies a missing baseline', async () => {
  const { ctx, tools } = harness();
  fpFilter(ctx);
  const result = JSON.parse(await tools.get('pre_validation_filter').execute({
    hypothesis: JSON.stringify({ target: 'https://api.fixture.test/items' }),
    scope: '*.fixture.test\n!admin.fixture.test',
    reconSummary: JSON.stringify({ items: [] }),
  }));
  assert.equal(result.pass, true);
  assert.deepEqual(result.suggested_baseline, { method: 'GET', url: 'https://api.fixture.test/items' });
});

test('hypothesis prompt loads learned skill filenames containing spaces', async () => {
  const domain = 'accuracy-fixture.invalid';
  const hunt = new URL(`../hunts/${domain}/`, import.meta.url);
  const skill = 'learned/h1-Improper Access Control - Generic-3533697';
  await mkdir(hunt, { recursive: true });
  try {
    await writeFile(new URL('skills-selected.json', hunt), JSON.stringify([{ skill }]));
    await writeFile(new URL('jev-decision.json', hunt), JSON.stringify({ next_action: 'select_and_test', skill, test_method: 'checklist_walk' }));
    execFileSync('bash', [new URL('../scripts/pipeline/hypothesis.sh', import.meta.url).pathname, domain]);
    const prompt = await readFile(new URL('hypothesis-prompt.txt', hunt), 'utf8');
    assert.match(prompt, /Public-Share Write-Policy Bypass/);
  } finally {
    await rm(hunt, { recursive: true, force: true });
  }
});
