import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, writeFile, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadSkills } from '../scripts/pipeline/jev-decide.mjs';
import { apply as skillRag } from '../plugins/dsh-skill-rag/index.js';
import { apply as skillLoader } from '../plugins/dsh-skill-loader/index.js';
import { apply as skillAdmission } from '../plugins/dsh-skill-admission/index.js';

test('committed reports enter the queue once, and only admitted classifier skills are loaded', async () => {
  const root = await mkdtemp(join(tmpdir(), 'bughive-reports-'));
  const reports = join(root, 'reports');
  const dsh = join(root, 'dsh');
  const learned = join(dsh, 'skills', 'learned');
  const hunt = new URL('../hunts/report-integration.invalid/', import.meta.url);
  const previous = process.env.BUGHIVE_DSH_DIR;
  try {
    await mkdir(reports);
    await mkdir(learned, { recursive: true });
    await writeFile(join(reports, 'h1-79.json'), JSON.stringify({ h1Id: '79', title: 'Fixture' }));
    await writeFile(join(reports, 'h1-80.json'), JSON.stringify({ h1Id: 'wrong', title: 'Invalid' }));
    const sync = () => JSON.parse(execFileSync('python3', ['intelligence/sync-report-queue.py'], {
      cwd: new URL('..', import.meta.url),
      env: { ...process.env, BUGHIVE_REPORTS_DIR: reports, BUGHIVE_DSH_DIR: dsh },
      encoding: 'utf8',
    }));
    assert.deepEqual(sync(), { reports_seen: 2, queued: 1, already_processed: 0, invalid: 1 });
    assert.equal(JSON.parse(await readFile(join(dsh, 'bounty-queue', 'h1-79.json'))).h1Id, '79');
    assert.equal(sync().queued, 0);

    process.env.BUGHIVE_DSH_DIR = dsh;
    await writeFile(join(learned, 'h1-cwe-79.md'), '---\nadmitted: 2026-01-01\n---\nDistinctive zebra endpoint traversal technique');
    await writeFile(join(learned, 'h1-cwe-80.md'), 'Unvetted zebra endpoint traversal technique');
    const skills = await loadSkills();
    assert.equal(skills.find(s => s.id === 'learned/h1-cwe-79')?.path, join(learned, 'h1-cwe-79.md'));
    assert.equal(skills.some(s => s.id === 'learned/h1-cwe-80'), false);

    const tools = new Map();
    skillRag({ tools: { register: t => tools.set(t.name, t) } }, {
      skillsRoot: join(root, 'empty-skills'), externalLearnedDir: learned, useEmbeddings: false,
    });
    const ranked = JSON.parse(await tools.get('retrieve_skills').execute({ query: 'Distinctive zebra endpoint traversal', k: 5 }));
    assert.equal(ranked.indexed_skills, 1);
    assert.equal(ranked.candidates[0]?.id, 'learned/h1-cwe-79');

    const loaderTools = new Map();
    skillLoader({ tools: { register: t => loaderTools.set(t.name, t) } }, {
      skillsRoot: join(root, 'empty-skills'), externalLearnedDir: learned,
    });
    const loaded = JSON.parse(await loaderTools.get('load_skills_for_target').execute({ profile: 'Distinctive zebra endpoint traversal' }));
    assert.equal(loaded.skills[0]?.source, 'learned/h1-cwe-79.md');
    assert.equal(loaded.candidates, 1);

    const admissionTools = new Map();
    skillAdmission({ tools: { register: t => admissionTools.set(t.name, t) } }, {
      skillsRoot: join(root, 'empty-skills'), externalLearnedDir: learned,
    });
    const candidate = join(root, 'candidate.md');
    await writeFile(candidate, 'Distinctive zebra endpoint traversal technique');
    const duplicate = JSON.parse(await admissionTools.get('dedupe_skill_candidate').execute({ path: candidate }));
    assert.equal(duplicate.duplicate, true);
    assert.equal(duplicate.closest, 'learned/h1-cwe-79.md');

    await mkdir(hunt, { recursive: true });
    await writeFile(new URL('skills-selected.json', hunt), JSON.stringify([{ skill: 'learned/h1-cwe-79' }]));
    await writeFile(new URL('jev-decision.json', hunt), JSON.stringify({
      next_action: 'select_and_test', skill: 'learned/h1-cwe-79', test_method: 'checklist_walk',
    }));
    execFileSync('bash', [new URL('../scripts/pipeline/hypothesis.sh', import.meta.url).pathname, 'report-integration.invalid'], {
      env: { ...process.env, BUGHIVE_DSH_DIR: dsh },
    });
    assert.match(await readFile(new URL('hypothesis-prompt.txt', hunt), 'utf8'), /Distinctive zebra endpoint traversal technique/);

    await mkdir(join(dsh, 'bounty-archive'));
    await writeFile(join(dsh, 'bounty-archive', 'h1-79.json'), '{}');
    assert.equal(sync().already_processed, 1);
  } finally {
    if (previous === undefined) delete process.env.BUGHIVE_DSH_DIR;
    else process.env.BUGHIVE_DSH_DIR = previous;
    await rm(hunt, { recursive: true, force: true });
    await rm(root, { recursive: true, force: true });
  }
});
