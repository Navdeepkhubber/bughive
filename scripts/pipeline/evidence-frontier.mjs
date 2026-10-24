#!/usr/bin/env node
/** Deterministic, read-only evidence selection for JEV. No requests are sent. */
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { scopeAllows } from '../../plugins/dsh-scope-guard/index.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const MAX_REPLAY = 24;
const HIT_PHASES = new Set(['13-secret-scan', '14-nuclei-scan', '15-mass-oneliners', '16-github-dorking']);
const PRIVATE = /(?:token|secret|password|passwd|apikey|api_key|authorization|session|cookie|jwt|code|signature|key)/i;
const INTERESTING = /(?:api|admin|auth|oauth|account|user|profile|upload|download|export|import|billing|payment|webhook|redirect|graphql|callback|file|report)/i;
const ID = /^(?:\d+|[0-9a-f]{8}-[0-9a-f-]{12,}|[0-9a-f]{16,})$/i;

function safeUrl(raw) {
  try {
    const u = new URL(raw);
    if (!['http:', 'https:'].includes(u.protocol)) return null;
    u.username = '';
    u.password = '';
    u.hash = '';
    for (const k of u.searchParams.keys()) if (PRIVATE.test(k)) u.searchParams.set(k, '<redacted>');
    return u;
  } catch { return null; }
}

export function routeKey(url, method = 'GET') {
  const u = safeUrl(url);
  if (!u) return null;
  const path = u.pathname.replace(/\/{2,}/g, '/').split('/').map(s => ID.test(s) ? ':id' : s).join('/');
  const params = [...new Set(u.searchParams.keys())].sort().join(',');
  return `${method.toUpperCase()} ${u.origin}${path}?${params}`;
}

function visit(node, cb, depth = 0) {
  if (depth > 7 || node == null) return;
  if (Array.isArray(node)) { node.forEach(x => visit(x, cb, depth + 1)); return; }
  if (typeof node !== 'object') return;
  if (typeof node.url === 'string') cb(node);
  for (const [key, value] of Object.entries(node)) if (key !== 'url' && key !== 'body' && key !== 'headers' && key !== 'raw') visit(value, cb, depth + 1);
}

export function mineJsParameters(files = {}) {
  const out = [];
  for (const [file, content] of Object.entries(files)) {
    const names = new Set();
    const text = String(content).slice(0, 2_000_000);
    for (const match of text.matchAll(/(?:searchParams\.(?:get|set|append)|URLSearchParams\([^)]*\)\.(?:get|set|append))\s*\(\s*['"]([A-Za-z_][\w-]{1,63})['"]/g)) names.add(match[1]);
    for (const match of text.matchAll(/[?&]([A-Za-z_][\w-]{0,63})=/g)) names.add(match[1]);
    for (const name of [...names].slice(0, 30)) out.push({ name, source: file,
      gate: 'Candidate from client code; first establish the owning route and baseline before one bounded probe.' });
  }
  return out.slice(0, 100);
}

export function buildFrontier({ recon = {}, scope = '', traffic = [], sourceHits = [], jsFiles = {} }) {
  const groups = new Map();
  const counts = {};
  for (const [phase, summary] of Object.entries(recon).sort()) {
    counts[phase] = Number(summary?.count ?? summary?.host_count ?? 0);
    visit(summary, item => {
      const u = safeUrl(item.url);
      if (!u || !scopeAllows(scope, u.hostname).allowed) return;
      const method = String(item.method || 'GET').toUpperCase();
      const key = routeKey(u.href, method);
      if (!key) return;
      let group = groups.get(key);
      if (!group) {
        group = { key, url: u.href, method, host: u.hostname, path: u.pathname,
          params: [...new Set(u.searchParams.keys())].sort(), phases: [], evidence: [], technologies: [], score: 0, signals: [] };
        groups.set(key, group);
      }
      for (const tech of (Array.isArray(item.tech) ? item.tech : [])) {
        if (typeof tech === 'string' && !group.technologies.includes(tech)) group.technologies.push(tech.slice(0, 100));
      }
      if (!group.phases.includes(phase)) group.phases.push(phase);
      if (group.evidence.length < 8) group.evidence.push({ phase, file: `recon/${phase}/summary.json`,
        status: item.unauth_status ?? item.status_code ?? item.status ?? null,
        keyword: item.matched_keyword || null, source: item.source || null,
        live: item.live === true });
    });
  }
  const replay = [];
  for (const [i, entry] of traffic.entries()) {
    const method = String(entry?.method || '').toUpperCase();
    const u = safeUrl(entry?.url);
    if (!u || !scopeAllows(scope, u.hostname).allowed || !['GET', 'HEAD'].includes(method)) continue;
    if (entry?.error || replay.length >= MAX_REPLAY) continue;
    const key = routeKey(u.href, method);
    replay.push({ key, method, url: u.href, evidence: `recon/proxy-capture.jsonl:${i + 1}`,
      experiment: 'Replay with owner, second authorized test identity, and anonymous session; compare private fields and object ownership.',
      prerequisites: ['two owned test identities', 'recorded expected owner response'],
      proof: 'A second identity retrieves owner-only data; response similarity alone is a lead.' });
    let group = groups.get(key);
    if (!group) {
      group = { key, url: u.href, method, host: u.hostname, path: u.pathname,
        params: [...new Set(u.searchParams.keys())].sort(), phases: [], evidence: [], technologies: [], score: 0, signals: [] };
      groups.set(key, group);
    }
    if (group.evidence.length < 8) group.evidence.push({ phase: 'proxy', file: `recon/proxy-capture.jsonl:${i + 1}`,
      status: null, keyword: null, source: 'proxy', live: true });
    if (!group.signals.includes('captured_workflow')) group.signals.push('captured_workflow');
  }
  const routes = [...groups.values()].map(g => {
    const hit = g.phases.some(p => HIT_PHASES.has(p));
    const interesting = INTERESTING.test(g.path) || g.params.some(p => INTERESTING.test(p));
    const changed = g.phases.includes('18-source-audit');
    const observed = g.evidence.some(e => e.phase === '04-http-probe' || e.phase === '07-js-analysis' ||
      e.source === 'html-extract' || e.live);
    const guessed = g.evidence.some(e => ['ffuf', 'sensitive-path'].includes(e.source));
    const archiveOnly = g.phases.every(p => p === '09-historical-data');
    g.eligible = observed || hit || changed;
    g.provenance = observed ? 'observed' : guessed ? 'generic_probe' : archiveOnly ? 'archive_only' : 'unconfirmed';
    if (hit) g.signals.push('tool_hit_requires_falsification');
    if (interesting) g.signals.push('interesting_surface_only');
    if (guessed && !observed) g.signals.push('needs_response_control');
    if (archiveOnly) g.signals.push('archived_only_recheck_reachability');
    if (g.params.length) g.signals.push('controllable_query');
    if (changed) g.signals.push('source_route_candidate');
    const status = g.evidence.map(e => e.status).filter(x => x != null);
    if (status.some(x => x === 401 || x === 403)) g.signals.push('auth_boundary');
    g.score = Math.min(10, (g.eligible ? 2 : 0) + (hit ? 4 : 0) + (interesting && g.eligible ? 2 : 0) +
      (g.params.length ? 1 : 0) + (g.signals.includes('captured_workflow') ? 2 : 0) +
      (g.signals.includes('auth_boundary') ? 1 : 0) + (changed ? 1 : 0));
    if (guessed && !observed) g.score = Math.min(g.score, 1);
    if (archiveOnly) g.score = Math.min(g.score, 1);
    g.next_experiment = g.signals.includes('captured_workflow') ? 'authorized identity swap replay' :
      g.params.length ? 'paired baseline and one parameter mutation' :
      hit ? 'inspect raw tool evidence and falsify before proof' : 'inspect observed behavior before selecting a test';
    g.proof_required = 'A class-specific validator must confirm impact; this route is only a lead.';
    if (g.phases.includes('07-js-analysis')) g.next_validator = 'If a DOM XSS lead has an executable payload, use validate_xss_browser; reflection is insufficient.';
    return g;
  }).sort((a,b) => b.score - a.score || a.key.localeCompare(b.key));
  const parameterCandidates = routes.filter(x => x.params.length && x.eligible).slice(0, 30).map(x => ({
    key: x.key, url: x.url, names: x.params, evidence: x.evidence[0]?.file,
    experiment: 'Use observed parameter names on this route with a paired baseline; do not spray unrelated hosts.'
  }));
  const technologyMatches = routes.filter(x => x.technologies.length || x.phases.includes('08-tech-fingerprint')).slice(0, 30).map(x => ({
    key: x.key, technologies: x.technologies, evidence: x.evidence.filter(e => e.phase === '08-tech-fingerprint' || e.phase === '04-http-probe'),
    gate: 'Only run a version-specific check after confirming product and version from raw evidence.'
  }));
  const sourceLeads = sourceHits.slice(0, 100).map((hit, i) => {
    const line = `${hit.message || ''} ${hit.next_step || ''}`;
    const route = line.match(/\/(?:api|admin|auth|user|upload|download|export|webhook)[\w/{}:.-]*/i)?.[0];
    const candidates = route ? routes.filter(r => r.path.startsWith(route)).slice(0, 5).map(r => r.key) : [];
    return { rule: hit.rule || '', source: `${hit.file || 'unknown'}:${hit.line || '?'}`,
      evidence: `recon/18-source-audit/items.jsonl:${i + 1}`, candidate_routes: candidates,
      reachability: candidates.length ? 'Candidate route match only; trace source call path and verify at runtime.' : 'No route match; establish reachability before testing.' };
  });
  return { version: 1, route_count: routes.length, phase_counts: counts, routes,
    parameter_candidates: parameterCandidates, technology_matches: technologyMatches,
    auth_replay_plans: replay, source_leads: sourceLeads,
    js_parameter_candidates: mineJsParameters(jsFiles) };
}

export function updateInventory(previous, current) {
  const inventoryRoutes = current.routes.filter(r => r.eligible);
  const keys = inventoryRoutes.map(r => r.key).sort();
  const descriptors = Object.fromEntries(inventoryRoutes.map(r => [r.key, JSON.stringify({
    statuses: [...new Set(r.evidence.map(e => e.status).filter(x => x != null))].sort(),
    technologies: [...r.technologies].sort(),
  })]));
  const fingerprint = JSON.stringify(descriptors);
  if (previous?.version === 2 && previous.fingerprint === fingerprint) return previous;
  const comparable = previous?.version === 2 && previous.descriptors;
  const old = new Set(comparable ? previous.routes || [] : []);
  const changed = comparable ? keys.filter(k => !old.has(k) || previous.descriptors[k] !== descriptors[k]) : [];
  return { version: 2, fingerprint, routes: keys, descriptors, changes: changed,
    removed: previous ? [...old].filter(k => !keys.includes(k)) : [],
    initial: !previous };
}

async function json(path, fallback) { try { return JSON.parse(await readFile(path, 'utf8')); } catch { return fallback; } }

export async function refreshFrontier(hd) {
  const scope = await readFile(join(hd, 'scope.txt'), 'utf8');
  const recon = {};
  for (const phase of await readdir(join(hd, 'recon')).catch(() => [])) {
    const value = await json(join(hd, 'recon', phase, 'summary.json'), null);
    if (value) recon[phase] = value;
  }
  const lines = (await readFile(join(hd, 'recon', 'proxy-capture.jsonl'), 'utf8').catch(() => '')).split('\n');
  const traffic = lines.flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } });
  const sourceLines = (await readFile(join(hd, 'recon', '18-source-audit', 'items.jsonl'), 'utf8').catch(() => '')).split('\n');
  const sourceHits = sourceLines.flatMap(line => { try { return [JSON.parse(line)]; } catch { return []; } });
  const jsFiles = {};
  const jsDir = join(hd, 'recon', '07-js-analysis');
  for (const name of (await readdir(jsDir).catch(() => [])).filter(n => /\.(?:js|mjs|html?)$/i.test(n)).slice(0, 50)) {
    const content = await readFile(join(jsDir, name), 'utf8').catch(() => '');
    jsFiles[`recon/07-js-analysis/${name}`] = content;
  }
  const manifest = (await readFile(join(jsDir, 'asset_fetch.tsv'), 'utf8').catch(() => '')).split('\n');
  for (const row of manifest.slice(0, 120)) {
    const [url, name] = row.split('\t');
    if (!name || !/^[a-zA-Z0-9._-]+$/.test(name)) continue;
    const parsed = safeUrl(url);
    if (!parsed || !scopeAllows(scope, parsed.hostname).allowed) continue;
    const content = await readFile(join(jsDir, 'assets', name), 'utf8').catch(() => '');
    if (content) jsFiles[`recon/07-js-analysis/assets/${name}`] = content;
  }
  const frontier = buildFrontier({ recon, scope, traffic, sourceHits, jsFiles });
  const previous = await json(join(hd, 'inventory-state.json'), null);
  const inventory = updateInventory(previous, frontier);
  frontier.changes = inventory.changes;
  frontier.removed = inventory.removed;
  frontier.initial_inventory = inventory.initial;
  const changed = new Set(inventory.changes);
  const sourceMatched = new Set(frontier.source_leads.flatMap(lead => lead.candidate_routes));
  for (const route of frontier.routes) if (changed.has(route.key)) {
    route.signals.push('changed_since_previous_inventory');
    route.score = Math.min(10, route.score + 2);
  }
  for (const route of frontier.routes) if (sourceMatched.has(route.key)) {
    route.signals.push('source_to_runtime_candidate');
    route.score = Math.min(10, route.score + 2);
  }
  frontier.routes.sort((a,b) => b.score - a.score || a.key.localeCompare(b.key));
  await writeFile(join(hd, 'evidence-frontier.json'), JSON.stringify(frontier, null, 2) + '\n');
  await writeFile(join(hd, 'inventory-state.json'), JSON.stringify(inventory, null, 2) + '\n');
  return frontier;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const domain = process.argv[2];
  if (!/^[a-z0-9.-]+$/i.test(domain || '')) throw new Error('domain required');
  const result = await refreshFrontier(join(ROOT, 'hunts', domain));
  console.log(JSON.stringify({ routes: result.route_count, changes: result.changes.length,
    replay_plans: result.auth_replay_plans.length, output: `hunts/${domain}/evidence-frontier.json` }));
}
