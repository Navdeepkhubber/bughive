import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, writeFile, mkdir, chmod, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts/push-ff.sh");
const WORKFLOW = join(ROOT, ".github/workflows/sync-reports-and-skills.yml");

function git(cwd, args, env = {}) {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "t",
      GIT_AUTHOR_EMAIL: "t@example.com",
      GIT_COMMITTER_NAME: "t",
      GIT_COMMITTER_EMAIL: "t@example.com",
      ...env,
    },
  });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed:\n${result.stdout}\n${result.stderr}`);
  }
  return result.stdout.trim();
}

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "bh-push-ff-"));
  const remote = join(root, "remote.git");
  const seed = join(root, "seed");
  git(root, ["init", "--bare", "-b", "main", remote]);
  git(root, ["init", "-b", "main", seed]);
  await writeFile(join(seed, "p"), "parent\n");
  git(seed, ["add", "p"]);
  git(seed, ["commit", "-m", "parent"]);
  await writeFile(join(seed, "reports.txt"), "report\n");
  await writeFile(join(seed, "skills.txt"), "skill\n");
  git(seed, ["add", "reports.txt", "skills.txt"]);
  git(seed, ["commit", "-m", "workflow sha"]);
  const pin = git(seed, ["rev-parse", "HEAD"]);
  const url = `file://${remote}`;
  git(seed, ["remote", "add", "origin", url]);
  git(seed, ["push", "-u", "origin", "main"]);
  return { root, remote, seed, pin, url };
}

// Matches actions/checkout@v4 with no ref: depth-1 fetch of the workflow SHA
// into origin/main, then checkout -B main.
function pinnedCheckout(root, url, pin) {
  const job = join(root, `job-${pin.slice(0, 7)}-${Math.random().toString(16).slice(2)}`);
  git(root, ["init", "-b", "main", job]);
  git(job, ["remote", "add", "origin", url]);
  git(job, ["fetch", "--no-tags", "--depth=1", "origin", `+${pin}:refs/remotes/origin/main`]);
  git(job, ["checkout", "--force", "-B", "main", "refs/remotes/origin/main"]);
  return job;
}

function runPush(job, env = {}) {
  return spawnSync("bash", [SCRIPT], {
    cwd: job,
    encoding: "utf8",
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: "t",
      GIT_AUTHOR_EMAIL: "t@example.com",
      GIT_COMMITTER_NAME: "t",
      GIT_COMMITTER_EMAIL: "t@example.com",
      PUSH_RETRY_SLEEP_SECONDS: "0",
      PUSH_ATTEMPTS: "5",
      ...env,
    },
  });
}

test("workflow commit steps push through scripts/push-ff.sh", async () => {
  const yml = await readFile(WORKFLOW, "utf8");
  assert.equal((yml.match(/bash scripts\/push-ff\.sh/g) || []).length, 3);
  assert.equal(yml.includes("\n            git push\n"), false);
});

test("rebases a depth-1 pin onto a main tip that moved", async () => {
  const fx = await fixture();
  try {
    const job = pinnedCheckout(fx.root, fx.url, fx.pin);
    await writeFile(join(fx.seed, "reports.txt"), "report-from-fetch\n");
    git(fx.seed, ["add", "reports.txt"]);
    git(fx.seed, ["commit", "-m", "Auto-update disclosed reports"]);
    git(fx.seed, ["push", "origin", "main"]);

    await writeFile(join(job, "skills.txt"), "skill-from-harvest\n");
    git(job, ["add", "skills.txt"]);
    git(job, ["commit", "-m", "Harvest staged skills"]);
    const rejected = spawnSync("git", ["push", "origin", "HEAD:main"], { cwd: job, encoding: "utf8" });
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /fetch first/);

    const pushed = runPush(job);
    assert.equal(pushed.status, 0, `${pushed.stdout}\n${pushed.stderr}`);
    assert.equal(git(fx.remote, ["show", "HEAD:reports.txt"]), "report-from-fetch");
    assert.equal(git(fx.remote, ["show", "HEAD:skills.txt"]), "skill-from-harvest");
    assert.equal(git(fx.remote, ["log", "-1", "--format=%s"]), "Harvest staged skills");
    assert.equal(git(fx.remote, ["rev-parse", "HEAD^"]), git(fx.seed, ["rev-parse", "HEAD"]));
  } finally {
    await rm(fx.root, { recursive: true, force: true });
  }
});

test("retries when main moves again between rebase and push", async () => {
  const fx = await fixture();
  try {
    const job = pinnedCheckout(fx.root, fx.url, fx.pin);
    await writeFile(join(job, "skills.txt"), "skill-from-harvest\n");
    git(job, ["add", "skills.txt"]);
    git(job, ["commit", "-m", "Harvest staged skills"]);

    const flag = join(fx.root, "rejected-once");
    const bin = join(fx.root, "bin");
    await mkdir(bin);
    const wrapper = join(bin, "git");
    await writeFile(wrapper, `#!/bin/bash
if [[ "$1" == "push" && ! -f ${JSON.stringify(flag)} ]]; then
  touch ${JSON.stringify(flag)}
  /usr/bin/git -C ${JSON.stringify(fx.seed)} commit --allow-empty -m "late push"
  /usr/bin/git -C ${JSON.stringify(fx.seed)} push origin main
  echo "! [rejected] main -> main (fetch first)" >&2
  exit 1
fi
exec /usr/bin/git "$@"
`);
    await chmod(wrapper, 0o755);

    const pushed = runPush(job, { PATH: `${bin}:${process.env.PATH}` });
    assert.equal(pushed.status, 0, `${pushed.stdout}\n${pushed.stderr}`);
    assert.match(pushed.stderr, /retrying/);
    const log = git(fx.remote, ["log", "--format=%s"]);
    assert.match(log, /^Harvest staged skills\nlate push\n/ );
    assert.equal(git(fx.remote, ["show", "HEAD:skills.txt"]), "skill-from-harvest");
  } finally {
    await rm(fx.root, { recursive: true, force: true });
  }
});

test("pushes the checked-out branch, not a hardcoded main", async () => {
  const fx = await fixture();
  try {
    git(fx.seed, ["checkout", "-b", "sync"]);
    git(fx.seed, ["push", "-u", "origin", "sync"]);
    const pin = git(fx.seed, ["rev-parse", "HEAD"]);
    const mainTip = git(fx.remote, ["rev-parse", "main"]);
    const job = pinnedCheckout(fx.root, fx.url, pin);
    git(job, ["branch", "-m", "sync"]);
    await writeFile(join(fx.seed, "reports.txt"), "on-sync\n");
    git(fx.seed, ["add", "reports.txt"]);
    git(fx.seed, ["commit", "-m", "sync moved"]);
    git(fx.seed, ["push", "origin", "sync"]);
    await writeFile(join(job, "skills.txt"), "from-sync-job\n");
    git(job, ["add", "skills.txt"]);
    git(job, ["commit", "-m", "job on sync"]);

    const pushed = runPush(job);
    assert.equal(pushed.status, 0, `${pushed.stdout}\n${pushed.stderr}`);
    assert.equal(git(fx.remote, ["rev-parse", "main"]), mainTip);
    assert.equal(git(fx.remote, ["show", "sync:skills.txt"]), "from-sync-job");
    assert.equal(git(fx.remote, ["show", "sync:reports.txt"]), "on-sync");
    assert.equal(git(fx.remote, ["log", "-1", "--format=%s", "sync"]), "job on sync");
  } finally {
    await rm(fx.root, { recursive: true, force: true });
  }
});

test("stops without pushing when the rebase conflicts", async () => {
  const fx = await fixture();
  try {
    const job = pinnedCheckout(fx.root, fx.url, fx.pin);
    await writeFile(join(fx.seed, "skills.txt"), "from-remote\n");
    git(fx.seed, ["add", "skills.txt"]);
    git(fx.seed, ["commit", "-m", "remote edit"]);
    git(fx.seed, ["push", "origin", "main"]);
    const remoteTip = git(fx.remote, ["rev-parse", "HEAD"]);

    await writeFile(join(job, "skills.txt"), "from-job\n");
    git(job, ["add", "skills.txt"]);
    git(job, ["commit", "-m", "job edit"]);

    const pushed = runPush(job, { PUSH_ATTEMPTS: "2" });
    assert.notEqual(pushed.status, 0);
    assert.match(pushed.stderr, /conflicted/);
    assert.equal(git(fx.remote, ["rev-parse", "HEAD"]), remoteTip);
    assert.equal(git(fx.remote, ["show", "HEAD:skills.txt"]), "from-remote");
    const status = git(job, ["status", "--porcelain=v1"]);
    assert.equal(status, "");
    assert.equal(spawnSync("test", ["!", "-d", join(job, ".git/rebase-merge")]).status, 0);
  } finally {
    await rm(fx.root, { recursive: true, force: true });
  }
});
