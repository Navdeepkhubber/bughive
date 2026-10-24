import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFrontier, mineJsParameters, routeKey, updateInventory } from '../scripts/pipeline/evidence-frontier.mjs';

const scope = '*.example.com\n!private.example.com';

test('groups route variants, enforces scope, and preserves provenance', () => {
  const f = buildFrontier({ scope, recon: {
    '04-http-probe': { results: { a: [{url:'https://app.example.com/api/users/42?id=42', status_code:401, tech:['Widget 2.1']}]} },
    '06-param-discovery': { items: [
      {url:'https://app.example.com/api/users/77?id=77'},
      {url:'https://private.example.com/api/users/77?id=77'},
      {url:'https://outside.test/api/users/77?id=77'},
    ] },
  }});
  assert.equal(f.route_count, 1);
  assert.equal(f.routes[0].key, 'GET https://app.example.com/api/users/:id?id');
  assert.deepEqual(f.routes[0].phases, ['04-http-probe', '06-param-discovery']);
  assert.ok(f.routes[0].signals.includes('auth_boundary'));
  assert.equal(f.technology_matches[0].technologies[0], 'Widget 2.1');
  assert.equal(f.parameter_candidates[0].names[0], 'id');
});

test('replay plans require safe captured methods and redact credentials', () => {
  const f = buildFrontier({ scope, recon: { p: {items:[{url:'https://app.example.com/account?token=secret&id=1'}]} }, traffic: [
    {method:'GET',url:'https://app.example.com/account?token=secret&id=1'},
    {method:'POST',url:'https://app.example.com/account/delete'},
    {method:'GET',url:'https://outside.test/account'},
  ]});
  assert.equal(f.auth_replay_plans.length, 1);
  assert.ok(!JSON.stringify(f).includes('secret'));
  assert.ok(f.auth_replay_plans[0].proof.includes('response similarity alone is a lead'));
});

test('inventory changes remain stable across repeated decisions and detect response changes', () => {
  const a = buildFrontier({scope,recon:{p:{items:[{url:'https://app.example.com/api/user',status:200}]}}});
  const first = updateInventory(null,a);
  assert.equal(first.initial,true);
  assert.deepEqual(first.changes,[]);
  assert.equal(updateInventory(first,a),first);
  const b = buildFrontier({scope,recon:{p:{items:[{url:'https://app.example.com/api/user',status:403}]}}});
  const second = updateInventory(first,b);
  assert.deepEqual(second.changes,['GET https://app.example.com/api/user?']);
  assert.equal(updateInventory(second,b),second);
});

test('source hits only map to observed routes and remain unverified leads', () => {
  const f = buildFrontier({scope,recon:{p:{items:[{url:'https://app.example.com/api/export'}]}},sourceHits:[
    {rule:'unsafe-file',file:'src/export.js',line:18,message:'handler /api/export reads user path'},
    {rule:'other',file:'src/other.js',line:3,message:'no route'},
  ]});
  assert.equal(f.source_leads[0].candidate_routes.length,1);
  assert.equal(f.source_leads[1].candidate_routes.length,0);
  assert.match(f.source_leads[0].reachability,/verify at runtime/);
  assert.equal(routeKey('javascript:alert(1)'),null);
});

test('mines parameter names only from observed local JavaScript', () => {
  const names = mineJsParameters({'recon/07-js-analysis/app.js':
    "u.searchParams.set('returnUrl', dest); fetch('/api?a=1&trace=2')"});
  assert.deepEqual(names.map(x => x.name), ['returnUrl','a','trace']);
  assert.ok(names.every(x => x.source.endsWith('app.js')));
});
