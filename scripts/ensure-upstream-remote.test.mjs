import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  describeUpstreamRemoteFailure,
  describeUpstreamRemotePlan,
  ensureUpstreamRemote,
  planUpstreamRemote,
  UPSTREAM_REMOTE_NAME,
  UPSTREAM_REMOTE_URL,
} from "./ensure-upstream-remote.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workspaces = [];

after(() => {
  for (const workspace of workspaces) rmSync(workspace, { recursive: true, force: true });
});

function newGitWorkspace() {
  const workspace = mkdtempSync(resolve(tmpdir(), "kuzushi-upstream-remote-"));
  workspaces.push(workspace);
  execFileSync("git", ["init", "--quiet"], { cwd: workspace, stdio: "ignore" });
  return workspace;
}

function remoteUrl(cwd) {
  try {
    return execFileSync("git", ["remote", "get-url", UPSTREAM_REMOTE_NAME], {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return null;
  }
}

test("planning is a pure decision over the remote's current URL", () => {
  assert.deepEqual(planUpstreamRemote(null), { action: "add", url: UPSTREAM_REMOTE_URL });
  assert.deepEqual(planUpstreamRemote(UPSTREAM_REMOTE_URL), {
    action: "keep",
    url: UPSTREAM_REMOTE_URL,
  });
  assert.deepEqual(planUpstreamRemote("git@github.com:me/codex.git"), {
    action: "diverged",
    url: "git@github.com:me/codex.git",
  });
});

test("a fresh clone gains the upstream remote and re-running is idempotent", () => {
  const workspace = newGitWorkspace();
  assert.equal(remoteUrl(workspace), null);

  assert.equal(ensureUpstreamRemote(workspace).action, "add");
  assert.equal(remoteUrl(workspace), UPSTREAM_REMOTE_URL);

  assert.equal(ensureUpstreamRemote(workspace).action, "keep");
  assert.equal(remoteUrl(workspace), UPSTREAM_REMOTE_URL);
});

test("a contributor's deliberate fork URL is reported, never overwritten", () => {
  const workspace = newGitWorkspace();
  const fork = "https://github.com/contributor/codex-fork.git";
  execFileSync("git", ["remote", "add", UPSTREAM_REMOTE_NAME, fork], {
    cwd: workspace,
    stdio: "ignore",
  });

  const plan = ensureUpstreamRemote(workspace);
  assert.equal(plan.action, "diverged");
  assert.equal(remoteUrl(workspace), fork);
  assert.match(describeUpstreamRemotePlan(plan), /expected https:\/\/github\.com\/openai\/codex/);
});

test("setup provisions the remote so no gate probes local git configuration", () => {
  const bootstrap = readFileSync(resolve(repoRoot, "scripts/bootstrap.sh"), "utf8");
  assert.match(bootstrap, /node scripts\/ensure-upstream-remote\.mjs/);

  const portContract = readFileSync(resolve(repoRoot, "scripts/check-port-contract.mjs"), "utf8");
  assert.doesNotMatch(portContract, /"remote"/);
});

test("a git failure is reported by reason, not as a stack trace", () => {
  const notARepo = mkdtempSync(resolve(tmpdir(), "kuzushi-upstream-remote-norepo-"));
  workspaces.push(notARepo);

  let failure;
  try {
    ensureUpstreamRemote(notARepo);
  } catch (error) {
    failure = error;
  }
  assert.ok(failure, "provisioning outside a git repository must fail");

  const described = describeUpstreamRemoteFailure(failure);
  assert.match(described, /^could not configure upstream-codex: /);
  assert.doesNotMatch(described, /\n/);
  assert.match(described, /not a git repository/i);
});

test("local git configuration runs before both bootstrap exits that could skip it", () => {
  const bootstrap = readFileSync(resolve(repoRoot, "scripts/bootstrap.sh"), "utf8");
  const gitConfigSection = bootstrap.indexOf('section "Configuring local git"');
  const strictGate = bootstrap.indexOf("(( STRICT == 1 && WARNINGS > 0 ))");
  const skipInstallExit = bootstrap.indexOf("(( SKIP_INSTALL == 1 ))");
  assert.ok(gitConfigSection > 0 && strictGate > 0 && skipInstallExit > 0);
  assert.ok(
    gitConfigSection < strictGate,
    "git configuration must precede the summary gate so --strict counts its warnings",
  );
  assert.ok(
    gitConfigSection < skipInstallExit,
    "git configuration must precede the --skip-install early exit",
  );
});
