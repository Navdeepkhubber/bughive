import test from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import https from "node:https";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { runScan } from "../plugins/dsh-scan/index.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function issueRevokedCert() {
  const dir = mkdtempSync(join(tmpdir(), "bh-crl-"));
  mkdirSync(join(dir, "newcerts"));
  writeFileSync(join(dir, "index.txt"), "");
  writeFileSync(join(dir, "serial"), "1000\n");
  writeFileSync(join(dir, "crlnumber"), "1000\n");
  const cnf = join(dir, "ca.cnf");
  writeFileSync(cnf, `[ ca ]
default_ca = CA
[ CA ]
dir = ${dir}
database = ${dir}/index.txt
new_certs_dir = ${dir}/newcerts
certificate = ${dir}/ca.crt
private_key = ${dir}/ca.key
serial = ${dir}/serial
crlnumber = ${dir}/crlnumber
default_md = sha256
default_days = 2
default_crl_days = 7
policy = pol
unique_subject = no
[ pol ]
commonName = supplied
`);
  const quiet = { stdio: "pipe" };
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-keyout", join(dir, "ca.key"), "-out", join(dir, "ca.crt"), "-days", "2", "-nodes", "-subj", "/CN=bughive-test-ca"], quiet);
  execFileSync("openssl", ["req", "-newkey", "rsa:2048", "-keyout", join(dir, "leaf.key"), "-out", join(dir, "leaf.csr"), "-nodes", "-subj", "/CN=revoked.local"], quiet);
  execFileSync("openssl", ["ca", "-batch", "-config", cnf, "-in", join(dir, "leaf.csr"), "-out", join(dir, "leaf.crt")], quiet);
  execFileSync("openssl", ["ca", "-batch", "-config", cnf, "-revoke", join(dir, "leaf.crt")], quiet);
  execFileSync("openssl", ["ca", "-batch", "-config", cnf, "-gencrl", "-out", join(dir, "ca.crl")], quiet);
  return dir;
}

test("seed files are original; staged harvest text is not promoted verbatim", async () => {
  const names = await readdir(join(ROOT, "skills/seeds"));
  for (const name of names) {
    if (!name.endsWith(".md")) continue;
    const text = await readFile(join(ROOT, "skills/seeds", name), "utf8");
    assert.equal(text.includes("STAGING ONLY"), false, name);
    assert.equal(text.includes("harvested:"), false, name);
  }
});

test("AWS example key is ignored and a non-allowlisted key stays unverified", async () => {
  const result = await runScan({
    paths: [join(ROOT, "canaries/secrets/keys.txt")],
    scopeText: "127.0.0.1",
  });
  assert.equal(result.ok, true, result.stats.verdict);
  const hits = result.findings.filter((item) => item.ruleId === "secret-aws-access-key");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].status, "unverified");
  assert.equal(result.confirmed.some((item) => item.ruleId === "secret-aws-access-key"), false);
  assert.equal(JSON.stringify(hits).includes("AKIAIOSFODNN7EXAMPLE"), false);
  assert.equal(JSON.stringify(hits).includes("AKIABUGHIVECANARY01"), false);
});

test("local login tautology is a confirmed SQLi hit", async () => {
  const child = spawn(process.execPath, [join(ROOT, "canaries/juice-login.mjs"), "--port", "18221"], { stdio: ["ignore", "pipe", "pipe"] });
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("login canary did not listen")), 5000);
    child.stdout.on("data", (buf) => {
      if (String(buf).includes("listening")) {
        clearTimeout(timer);
        resolve();
      }
    });
    child.on("exit", () => reject(new Error("login canary exited")));
  });
  try {
    const result = await runScan({ base: "http://127.0.0.1:18221", scopeText: "127.0.0.1" });
    const hit = result.confirmed.find((item) => item.ruleId === "sqli-login-boolean");
    assert.ok(hit, result.stats.checks.filter((item) => item.id === "sqli-login-boolean").map((item) => item.detail).join("; "));
    assert.equal(hit.status, "verified");
    assert.ok(hit.request && hit.response);
  } finally {
    child.kill();
  }
});

test("a locally revoked certificate is a confirmed TLS hit", async () => {
  const dir = issueRevokedCert();
  const server = https.createServer(
    { key: readFileSync(join(dir, "leaf.key")), cert: readFileSync(join(dir, "leaf.crt")) },
    (_req, res) => res.end("ok"),
  );
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  try {
    const result = await runScan({
      scopeText: "127.0.0.1",
      tls: {
        host: "127.0.0.1",
        port,
        servername: "revoked.local",
        caFile: join(dir, "ca.crt"),
        crlFile: join(dir, "ca.crl"),
      },
    });
    const hit = result.confirmed.find((item) => item.ruleId === "tls-cert-revoked");
    assert.ok(hit, JSON.stringify(result.stats.checks.filter((item) => item.id === "tls-cert-revoked")));
    assert.match(hit.proof, /revoked/i);
    assert.ok(hit.response.body.length > 0);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(dir, { recursive: true, force: true });
  }
});

test("lodash 4.17.20 is confirmed against live OSV advisories", async () => {
  const result = await runScan({
    packageJson: join(ROOT, "canaries/lockfile/package.json"),
    scopeText: "127.0.0.1",
  });
  assert.equal(result.stats.errors, 0, JSON.stringify(result.stats.checks));
  const hit = result.confirmed.find((item) => item.ruleId === "sca-osv-npm");
  assert.ok(hit, result.stats.verdict);
  assert.ok(hit.advisories.includes("GHSA-35jh-r3h4-6jhm"), hit.advisories.join(","));
  assert.match(hit.response.body, /GHSA-35jh-r3h4-6jhm/);
  assert.equal(result.stats.modules["osv-scanner"], "not-installed");
});

test("expired.badssl.com is a confirmed hit and revoked.badssl.com is not invented", async () => {
  const result = await runScan({
    tlsHosts: ["expired.badssl.com", "revoked.badssl.com"],
    scopeText: "expired.badssl.com\nrevoked.badssl.com",
  });
  const expired = result.confirmed.find((item) => item.ruleId === "tls-cert-expired" && item.asset.includes("expired.badssl.com"));
  assert.ok(expired, JSON.stringify(result.stats.checks.filter((item) => item.id === "tls-cert-expired")));
  assert.match(expired.response.body, /CERT_HAS_EXPIRED/);
  const revokedLog = result.stats.checks.find((item) => item.id === "tls-cert-revoked" && item.detail.includes("revoked.badssl.com"));
  assert.ok(revokedLog, "revocation check did not run");
  assert.notEqual(revokedLog.result, "skipped");
  if (revokedLog.result === "verified") {
    assert.ok(result.confirmed.some((item) => item.asset.includes("revoked.badssl.com")));
  } else {
    assert.equal(result.confirmed.some((item) => item.ruleId === "tls-cert-revoked" && item.asset.includes("revoked.badssl.com")), false);
    assert.match(revokedLog.detail, /verification_skipped|certificate revoked|error:/);
  }
});
