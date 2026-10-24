import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, rm } from 'node:fs/promises';
import {
  runGate,
  reportEmissionDecision,
  demoteToLead,
  promoteLeads,
  chainHypothesesFor,
} from '../plugins/dsh-triage-gate/index.js';
import {
  assessClassMatrix,
  assessMarker,
  assessBodyDiff,
  assessSignals,
  decideTiming,
  timingDiscipline,
} from '../plugins/dsh-validators/index.js';
import { apply as validators } from '../plugins/dsh-validators/index.js';
import { auditClaims } from '../plugins/dsh-claim-audit/index.js';
import { decide, heuristicPlan, plannerMode } from '../scripts/pipeline/jev-decide.mjs';

const yes = {
  q1Reproducible: true,
  q2ImpactAccepted: true,
  q3InScope: true,
  q4NoPrivilegedAccess: true,
  q5NotKnown: true,
  q6ProvenImpact: true,
  q7NotAlwaysRejected: true,
  q8Identity: true,
};

test('Q8 confirms IDOR from a second session and rejects missing-auth, same body, and stale credentials', () => {
  const idor = runGate({
    title: 'IDOR in GET /api/users/{id} lets one account read another',
    impact: 'other-user email and api key',
    answers: yes,
    identity: { session: 'alice', anonymous: false, crossAccount: true, staleCredential: false, otherUserPii: true },
  });
  assert.equal(idor.passed, true);
  assert.equal(idor.disposition, 'finding');
  assert.equal(idor.identity.classification, 'idor');

  const missingAuth = runGate({
    title: 'IDOR in GET /admin/users',
    impact: 'user table',
    answers: yes,
    identity: { session: 'none', anonymous: true, crossAccount: false, otherUserPii: true },
  });
  assert.equal(missingAuth.passed, false);
  assert.equal(missingAuth.identity.classification, 'missing-auth');
  assert.equal(missingAuth.disposition, 'lead');
  assert.equal(missingAuth.kept, true);

  const same = runGate({
    title: 'IDOR in GET /api/users/{id}',
    impact: 'profile',
    answers: yes,
    identity: { session: 'alice', anonymous: false, crossAccount: true, sameData: true, otherUserPii: false },
  });
  assert.equal(same.passed, false);
  assert.equal(same.identity.classification, 'same-data');

  const stale = runGate({
    title: 'IDOR in GET /api/users/{id}',
    impact: 'profile',
    answers: yes,
    identity: { session: 'alice', staleCredential: true, crossAccount: true, otherUserPii: true },
  });
  assert.equal(stale.passed, false);
  assert.equal(stale.identity.classification, 'stale-cred');
  assert.equal(stale.disposition, 'lead');
});

test('hard-deny blocks DNS-only SSRF, self-XSS, and headers even with a chain; open redirect needs a partner', () => {
  for (const title of ['DNS-only SSRF callback on /fetch', 'Self-XSS in the profile bio', 'Missing HSTS header on the app']) {
    const killed = runGate({
      title,
      impact: 'none shown',
      answers: yes,
      hasChain: true,
      chain: 'claimed chain to oauth account takeover',
    });
    assert.equal(killed.passed, false, title);
    assert.equal(killed.tag, 'standalone_invalid');
    assert.equal(killed.disposition, 'lead');
    assert.equal(killed.kept, true);
  }

  const alone = reportEmissionDecision({ title: 'Open redirect in /login?r=', impact: 'sends the browser away', class: 'open-redirect' });
  assert.equal(alone.emit, false);
  assert.equal(alone.tag, 'needs_chain');
  assert.equal(alone.disposition, 'lead');
  assert.ok(alone.chain_hypotheses.length === 1);

  const chained = reportEmissionDecision(
    { title: 'Open redirect in /login?r=', impact: 'account takeover', class: 'open-redirect' },
    { steps: ['redirect_uri', 'oauth code'] },
  );
  assert.equal(chained.emit, true);

  const hypotheses = chainHypothesesFor([{ id: 'r1', class: 'open-redirect', title: 'Open redirect in /go' }]);
  assert.equal(hypotheses.length, 1);
  assert.equal(hypotheses[0].source_id, 'r1');
  assert.equal(chainHypothesesFor([{ title: 'Self-XSS in bio' }]).length, 0);
});

test('class matrices confirm race balance changes and IDOR other-user PII, and demote kills to leads', () => {
  const race = assessClassMatrix('race-condition', { balanceBefore: 100, balanceAfter: 80 });
  assert.equal(race.matrix_result, 'confirm');
  assert.equal(race.matched_confirm[0], 'balance_changed');

  const serialized = assessClassMatrix('race', { uniqueConstraint: true, appliedCount: 2 });
  assert.equal(serialized.matrix_result, 'kill');
  assert.equal(serialized.disposition, 'lead');
  assert.equal(serialized.kept, true);

  const idor = assessClassMatrix('idor', {
    ownBody: '{"name":"alice"}',
    probeBody: '{"name":"bob","apiKey":"AKIAI44QH8DHBEXAMPLE"}',
    victimMarker: 'AKIAI44QH8DHBEXAMPLE',
    otherUserPii: true,
  });
  assert.equal(idor.matrix_result, 'confirm');
  assert.equal(idor.matched_confirm[0], 'other_user_pii');

  const own = assessClassMatrix('idor', { sameData: true, probeBody: '{"name":"alice"}', ownBody: '{"name":"alice"}' });
  assert.equal(own.matrix_result, 'kill');
  assert.equal(own.disposition, 'lead');
});

test('marker, body-diff, n>=10 timing, and two-signal rules demote weak proof to a lead', () => {
  assert.equal(assessMarker('AAAA', '', 'AAAA').usable, false);
  assert.equal(assessMarker('test', '', 'test').usable, false);
  assert.equal(assessMarker('javascript', 'javascript:void(0)', 'javascript:void(0)').in_baseline, true);
  const marker = assessMarker('bhMarker9f3a', 'hello', 'hello bhMarker9f3a');
  assert.equal(marker.usable, true);

  const statusOnly = assessBodyDiff({ status: 403, body: 'nope' }, { status: 200, body: 'nope' });
  assert.equal(statusOnly.status_only, true);
  assert.equal(statusOnly.ok, false);
  assert.equal(assessBodyDiff({ status: 200, body: 'alice' }, { status: 200, body: 'bob' }).ok, true);

  const baseline = Array.from({ length: 10 }, () => ({ ms: 100 }));
  const probe = Array.from({ length: 10 }, () => ({ ms: 400 }));
  assert.equal(timingDiscipline(baseline, probe).disciplined, true);
  const thin = decideTiming([{ ms: 100 }, { ms: 110 }, { ms: 105 }], [{ ms: 5200 }, { ms: 5150 }, { ms: 5300 }], 5000);
  assert.equal(thin.validated, true, 'a real delay is still detected');
  assert.equal(thin.discipline.disciplined, false, 'n=3 stays below the timing bar');

  assert.equal(assessSignals('blind-sqli', [{ mode: 'timing', validated: true }]).disposition, 'lead');
  const both = assessSignals('blind-sqli', [
    { mode: 'timing', validated: true },
    { mode: 'boolean', validated: true },
  ]);
  assert.equal(both.disposition, 'confirm');
  assert.equal(assessSignals('ssrf', [{ mode: 'dns', validated: true }]).tag, 'standalone_invalid');
});

test('IDOR route confirms other-user PII and claim-audit accepts a dual-session record', async () => {
  const tools = new Map();
  validators({ tools: { register: (t) => tools.set(t.name, t) } });
  const confirmed = JSON.parse(await tools.get('validate_by_class').execute({
    bugClass: 'idor',
    spec: JSON.stringify({
      otherUserPii: true,
      victimMarker: 'AKIAI44QH8DHBEXAMPLE',
      ownBody: '{"name":"alice"}',
      probeBody: '{"name":"bob","apiKey":"AKIAI44QH8DHBEXAMPLE"}',
    }),
  }));
  assert.equal(confirmed.route, 'idor-identity');
  assert.equal(confirmed.validated, true);
  assert.equal(confirmed.disposition, 'confirm');

  const manual = JSON.parse(await tools.get('validate_by_class').execute({ bugClass: 'idor', spec: '{}' }));
  assert.equal(manual.route, 'manual');
  assert.equal(manual.validated, false);

  const line = JSON.stringify({
    kind: 'identity',
    technique: 'idor',
    summary: 'GET /api/users/2 -> 200',
    detail: { method: 'GET', url: 'https://fixture.test/api/users/2' },
    session_a: 'alice',
    session_b: 'bob',
    digest_a: 'hash-alice',
    digest_b: 'hash-bob',
    other_user_pii: true,
  });
  const request = JSON.stringify({
    kind: 'request',
    summary: 'GET /api/users/2 -> 200',
    detail: { method: 'GET', url: 'https://fixture.test/api/users/2' },
  });
  const proved = auditClaims('Confirmed IDOR on GET /api/users/2.', `${request}\n${line}`);
  assert.equal(proved.pass, true);
  assert.equal(proved.unverifiable_count, 0);
  assert.equal(proved.claims.some((c) => c.technique === 'idor' && c.status === 'supported'), true);

  const unproved = auditClaims('Confirmed IDOR on GET /api/users/2.', request);
  assert.equal(unproved.pass, false);
  assert.equal(unproved.unverifiable_count, 1);
});

test('demoted leads keep their payload and promote when a sibling partner lands', () => {
  const lead = demoteToLead(
    { id: 'L1', title: 'Open redirect in /go', class: 'open-redirect', payload: 'next=https://evil.example' },
    'needs a partner',
    ['oauth', 'ato'],
  );
  assert.equal(lead.disposition, 'lead');
  assert.equal(lead.kept, true);
  assert.equal(lead.payload, 'next=https://evil.example');

  const waiting = promoteLeads([{ ...lead, confirm_signal: true }], []);
  assert.equal(waiting.promoted.length, 0);
  assert.equal(waiting.still_leads.length, 1);

  const ready = promoteLeads(
    [{ ...lead, confirm_signal: true }],
    [{ class: 'oauth', title: 'OAuth code stolen via redirect_uri', disposition: 'finding' }],
  );
  assert.equal(ready.promoted.length, 1);
  assert.equal(ready.promoted[0].disposition, 'finding');
  assert.equal(ready.promoted[0].payload, lead.payload);
});

test('heuristic decide runs with no API key and spawns a chain hypothesis', async () => {
  assert.equal(plannerMode({ BUGHIVE_PLANNER: '', TYPESAFE_API_KEY: '' }), 'heuristic');
  const skills = [{ id: 'seeds/idor', key: 'seeds__idor', blurb: 'swap ids' }];
  const planned = heuristicPlan({
    legal: [],
    recon: { '06-param-discovery': { count: 1, items: [{ url: 'https://app.example/api/users?id=1' }] } },
    keyword: [{ skill: 'seeds/idor', score: 4 }],
    hasKeyword: true,
    counts: { hypotheses: 0, hypotheses_pass: 0, hypotheses_real: 0, validated: 1, chains: 0, reports: 0, approved: 0 },
    validatedItems: [{ id: 'r1', class: 'open-redirect', title: 'Open redirect in /go' }],
  }, skills);
  assert.equal(planned.routing.answers.next_action.choice, 'chain');
  assert.equal(planned.chain_hypotheses.length, 1);

  const domain = 'precision-planner.invalid';
  const hunt = new URL(`../hunts/${domain}/`, import.meta.url);
  await mkdir(hunt, { recursive: true });
  try {
    const out = await decide(domain, { planner: 'heuristic' });
    assert.equal(out.planner, 'heuristic');
    assert.equal(out.source, 'heuristic');
    assert.equal(out.next_action, 'deepen_recon');
    assert.match(out.executor.command, /recon-01/);
    assert.equal(out.executor.kind, 'bash');
  } finally {
    await rm(hunt, { recursive: true, force: true });
  }
});
