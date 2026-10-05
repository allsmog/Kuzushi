import { execFileSync, spawnSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export function selectQualityBase(runs, currentRunId, branch, isAncestor) {
  const prior = runs.filter(
    (run) =>
      run.conclusion === "success" &&
      String(run.id) !== String(currentRunId) &&
      run.head_branch === branch &&
      /^[a-f0-9]{40}$/.test(run.head_sha),
  );
  prior.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
  const run = prior.find((candidate) => isAncestor(candidate.head_sha));
  if (!run)
    throw Error(
      "No successful ancestral Full CI baseline; supply quality_base_ref explicitly for the initial run",
    );
  return { base: run.head_sha, sourceRunId: run.id };
}

const git = (...args) => execFileSync("git", args, { encoding: "utf8", timeout: 30_000 }).trim();

function isAncestor(base, head) {
  const result = spawnSync("git", ["merge-base", "--is-ancestor", base, head]);
  if (result.status === 0) return true;
  if (result.status === 1) return false;
  throw result.error ?? Error("could not verify quality baseline ancestry");
}

function resolveBaseline(head) {
  const explicit = process.env.QUALITY_BASE_REF;
  if (explicit)
    return {
      base: git("rev-parse", "--verify", "--end-of-options", `${explicit}^{commit}`),
      sourceRunId: null,
    };
  const repo = process.env.GITHUB_REPOSITORY;
  const branch = process.env.GITHUB_REF_NAME;
  if (!repo || !branch) throw Error("quality interval requires repository and branch identity");
  const endpoint = `repos/${repo}/actions/workflows/ci-full.yml/runs?branch=${encodeURIComponent(branch)}&status=success&per_page=100`;
  const receipt = JSON.parse(
    execFileSync("gh", ["api", endpoint], {
      encoding: "utf8",
      timeout: 30_000,
      maxBuffer: 4 * 1024 * 1024,
    }),
  );
  return selectQualityBase(receipt.workflow_runs, process.env.GITHUB_RUN_ID, branch, (base) =>
    isAncestor(base, head),
  );
}

function main() {
  const head = git("rev-parse", "HEAD");
  const baseline = resolveBaseline(head);
  if (!isAncestor(baseline.base, head))
    throw Error("quality baseline is not an ancestor of the tested commit");
  const count = git("rev-list", "--count", `${baseline.base}..${head}`);
  if (!process.env.GITHUB_OUTPUT) throw Error("GITHUB_OUTPUT is required");
  appendFileSync(process.env.GITHUB_OUTPUT, `base=${baseline.base}\n`);
  console.log(JSON.stringify({ ...baseline, head, commits: Number(count) }));
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) main();
