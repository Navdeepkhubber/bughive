#!/usr/bin/env node
/** Refuse stage marks that are not the current JEV executor's completed work. */
import { readFile, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { CRITICAL_CLASSES } from '../../plugins/dsh-coverage/index.js';

async function json(path) { try { return JSON.parse(await readFile(path, 'utf8')); } catch { return null; } }
async function fresh(path, since) { try { return (await stat(path)).mtimeMs >= since; } catch { return false; } }
async function arrayArtifact(path, since) {
  return await fresh(path, since) && Array.isArray(await json(path));
}

export async function checkStageMark(hd, stage) {
  const decisionPath = join(hd, 'jev-decision.json');
  const decision = await json(decisionPath);
  if (!decision) return { allowed: false, reason: 'no JEV decision recorded' };
  const executor = decision.executor || {};
  if (executor.kind === 'halt' || decision.next_action === 'human_gate')
    return { allowed: false, reason: 'current JEV decision is human_gate; obtain a new decision before marking work' };
  if (executor.stage !== stage)
    return { allowed: false, reason: `current JEV executor is ${executor.stage || 'none'}, not ${stage}` };
  const since = (await stat(decisionPath)).mtimeMs;
  const requiredArray = {
    hypothesis: 'hypotheses.json', prefilter: 'hypotheses-pass.json',
    falsifier: 'hypotheses-real.json', proof: 'validated.json', chain: 'chains.json',
  }[stage];
  if (requiredArray && !(await arrayArtifact(join(hd, requiredArray), since)))
    return { allowed: false, reason: `${requiredArray} must be a JSON array written after this decision` };
  if (stage === 'skills' && !(await arrayArtifact(join(hd, 'skills-selected.json'), since)))
    return { allowed: false, reason: 'skills-selected.json is missing or stale' };
  if (stage.startsWith('recon-')) {
    const phase = decision.recon_phase;
    if (!phase || !(await fresh(join(hd, 'recon', phase, 'summary.json'), since)))
      return { allowed: false, reason: 'recon summary is missing or stale' };
  }
  if (stage === 'batch-step' && !(await fresh(join(hd, 'batch', 'state.json'), since)))
    return { allowed: false, reason: 'batch state was not advanced after this decision' };
  if (stage === 'report' || stage === 'quality') {
    const dir = join(hd, 'reports', ...(stage === 'quality' ? ['approved'] : []));
    const names = await readdir(dir).catch(() => []);
    if (!names.some((name) => name.endsWith('.md')))
      return { allowed: false, reason: `${stage} produced no Markdown report` };
  }
  if (stage === 'deliver') {
    if (!(await fresh(join(hd, 'SUMMARY.md'), since)))
      return { allowed: false, reason: 'SUMMARY.md is missing or stale' };
    const matrix = await json(join(hd, 'coverage.json'));
    if (!matrix?.cells || !Array.isArray(matrix.assets) || !Array.isArray(matrix.classes))
      return { allowed: false, reason: 'coverage matrix missing' };
    const incomplete = matrix.assets.some((asset) => matrix.classes.some((klass) =>
      CRITICAL_CLASSES.includes(klass) && !['tested', 'lead', 'finding', 'n/a'].includes(matrix.cells[`${klass}|${asset}`]?.status)));
    if (incomplete) return { allowed: false, reason: 'critical coverage includes untested or blocked cells' };
    const batch = await json(join(hd, 'batch', 'state.json'));
    if (batch && !batch.complete) return { allowed: false, reason: 'batch recon is incomplete' };
  }
  return { allowed: true, stage, decision_action: decision.next_action };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [hd, stage] = process.argv.slice(2);
  const result = await checkStageMark(hd, stage);
  console.log(JSON.stringify(result));
  if (!result.allowed) process.exitCode = 1;
}
