import { execFileSync, spawnSync } from "node:child_process";
import { lstatSync, mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { GroundTruthDataset } from "./types.js";

const GIT_TIMEOUT_MS = 5_000;
const CONTENT_PROOF_TIMEOUT_MS = 60_000;
const GIT_OUTPUT_LIMIT_BYTES = 64 * 1024;
const GIT_PATH_OUTPUT_LIMIT_BYTES = 32 * 1024 * 1024;
const FULL_COMMIT = /^(?:[a-f\d]{40}|[a-f\d]{64})$/iu;

interface DatasetCheckoutOptions {
  /** Permit only Kuzushi-owned ignored state created by the just-finished scan. */
  allowGeneratedKuzushiState?: boolean;
}

/** Prove that a live benchmark will execute against the declared clean corpus. */
export function assertDatasetCheckout(
  datasetDir: string,
  dataset: GroundTruthDataset,
  options: DatasetCheckoutOptions = {},
): string {
  const repoDir = join(datasetDir, "repo");
  const checkout = verifiedCheckoutRoot(repoDir);
  assertDeclaredRemote(checkout, dataset.repoUrl);
  const head = git(checkout, ["rev-parse", "--verify", "HEAD^{commit}"]);
  assertDeclaredRevision(checkout, head, dataset.repoRef);
  assertCleanCheckout(checkout, repoDir, options);
  return head;
}

function verifiedCheckoutRoot(repoDir: string): string {
  const metadata = lstatSync(repoDir);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`Dataset repo must be a non-symlink directory: ${repoDir}`);
  }

  const checkout = realpathSync(repoDir);
  const gitRoot = realpathSync(git(checkout, ["rev-parse", "--show-toplevel"]));
  if (gitRoot !== checkout) {
    throw new Error(`Dataset repo must be the Git worktree root: ${repoDir}`);
  }
  return checkout;
}

function assertDeclaredRevision(repoDir: string, head: string, repoRef: string): void {
  if (!FULL_COMMIT.test(repoRef)) {
    throw new Error("Dataset repoRef must be an immutable full commit digest");
  }
  const declared = git(repoDir, ["rev-parse", "--verify", `${repoRef}^{commit}`]);
  if (head !== declared) {
    throw new Error(
      `Dataset checkout HEAD ${head} does not match declared repoRef ${repoRef} (${declared})`,
    );
  }
}

function assertCleanCheckout(
  repoDir: string,
  displayPath: string,
  options: DatasetCheckoutOptions,
): void {
  assertNonSparseCheckout(repoDir);
  assertOrdinaryIndexFlags(repoDir);
  assertNoTrackedSubmodules(repoDir);
  const status = git(repoDir, ["status", "--porcelain=v1", "--untracked-files=all"]);
  if (status.length > 0) {
    throw new Error(`Dataset checkout is dirty; restore ${displayPath} before benchmarking`);
  }
  assertIgnoredUntrackedPolicy(repoDir, options);
  assertTrackedBytesMatchHead(repoDir, displayPath);
}

function assertNoTrackedSubmodules(repoDir: string): void {
  const entries = gitPaths(repoDir, ["ls-files", "-s", "-z", "--"]);
  if (entries.some((entry) => entry.startsWith("160000 "))) {
    throw new Error("Dataset checkout must not contain tracked Git submodules");
  }
}

function assertNonSparseCheckout(repoDir: string): void {
  const sparse = optionalGit(repoDir, ["config", "--get", "--bool", "core.sparseCheckout"]);
  if (sparse === "true") {
    throw new Error("Dataset checkout must not use sparse checkout");
  }
}

function assertOrdinaryIndexFlags(repoDir: string): void {
  const records = gitPaths(repoDir, ["ls-files", "-v", "-z", "--"]);
  const flagged = records.find((record) => record.length > 0 && record[0] !== "H");
  if (flagged) {
    throw new Error(
      "Dataset checkout contains non-default index flags such as assume-unchanged or skip-worktree",
    );
  }
}

function assertIgnoredUntrackedPolicy(repoDir: string, options: DatasetCheckoutOptions): void {
  const ignored = gitPaths(repoDir, [
    "ls-files",
    "--others",
    "--ignored",
    "--exclude-standard",
    "-z",
    "--",
  ]);
  const unexpected = ignored.find(
    (path) => !options.allowGeneratedKuzushiState || !path.startsWith(".kuzushi/"),
  );
  if (unexpected) {
    throw new Error(
      `Dataset checkout contains ignored untracked content outside the canonical corpus: ${unexpected}`,
    );
  }
}

function assertTrackedBytesMatchHead(repoDir: string, displayPath: string): void {
  const scratch = mkdtempSync(join(tmpdir(), "kuzushi-benchmark-index-"));
  const indexPath = join(scratch, "head.index");
  const env = { ...process.env, GIT_INDEX_FILE: indexPath };
  try {
    runGitProof(repoDir, ["read-tree", "HEAD"], env, "materialize the HEAD tree");
    runGitProof(
      repoDir,
      ["update-index", "--really-refresh"],
      env,
      "hash the worktree against the HEAD tree",
    );
    assertWorktreeMatchesHead(repoDir, displayPath, env);
  } catch (error) {
    throw contentProofError(error);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

function assertWorktreeMatchesHead(
  repoDir: string,
  displayPath: string,
  env: NodeJS.ProcessEnv,
): void {
  const comparison = spawnSync("git", worktreeComparisonArgs(repoDir), {
    env,
    encoding: "utf8",
    timeout: CONTENT_PROOF_TIMEOUT_MS,
    maxBuffer: GIT_OUTPUT_LIMIT_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (comparison.error) throw comparison.error;
  if (comparison.status === 1) {
    throw new Error(
      `Dataset checkout bytes differ from HEAD; restore ${displayPath} before benchmarking`,
    );
  }
  if (comparison.status !== 0) {
    throw new Error(`git diff-files exited with status ${comparison.status}: ${comparison.stderr}`);
  }
}

function worktreeComparisonArgs(repoDir: string): string[] {
  return [
    "-C",
    resolve(repoDir),
    "diff-files",
    "--quiet",
    "--no-ext-diff",
    "--ignore-submodules=none",
    "--",
  ];
}

function contentProofError(error: unknown): Error {
  if (error instanceof Error && error.message.startsWith("Dataset checkout bytes differ")) {
    return error;
  }
  return new Error(`Could not prove dataset checkout bytes match HEAD: ${message(error)}`);
}

function runGitProof(
  repoDir: string,
  args: string[],
  env: NodeJS.ProcessEnv,
  purpose: string,
): void {
  const result = spawnSync("git", ["-C", resolve(repoDir), ...args], {
    env,
    encoding: "utf8",
    timeout: CONTENT_PROOF_TIMEOUT_MS,
    maxBuffer: GIT_OUTPUT_LIMIT_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`Could not ${purpose}: ${result.stderr.trim() || `status ${result.status}`}`);
  }
}

function gitPaths(repoDir: string, args: string[]): string[] {
  const output = execFileSync("git", ["-C", resolve(repoDir), ...args], {
    encoding: "utf8",
    timeout: CONTENT_PROOF_TIMEOUT_MS,
    maxBuffer: GIT_PATH_OUTPUT_LIMIT_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
  });
  return output.split("\0").filter((record) => record.length > 0);
}

function optionalGit(repoDir: string, args: string[]): string | null {
  const result = spawnSync("git", ["-C", resolve(repoDir), ...args], {
    encoding: "utf8",
    timeout: GIT_TIMEOUT_MS,
    maxBuffer: GIT_OUTPUT_LIMIT_BYTES,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) throw result.error;
  if (result.status === 1) return null;
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} exited with status ${result.status}: ${result.stderr}`);
  }
  return result.stdout.trim();
}

function assertDeclaredRemote(repoDir: string, declaredUrl: string): void {
  if (new URL(declaredUrl).protocol === "fixture:") return;
  const actual = git(repoDir, ["config", "--get", "remote.origin.url"]);
  if (normalizedRepositoryUrl(actual) !== normalizedRepositoryUrl(declaredUrl)) {
    throw new Error(`Dataset remote ${actual} does not match declared repoUrl ${declaredUrl}`);
  }
}

function normalizedRepositoryUrl(value: string): string {
  const url = new URL(value);
  const path = url.pathname.replace(/\.git$/iu, "").replace(/\/$/u, "");
  return `${url.protocol}//${url.host.toLowerCase()}${path}`;
}

function git(repoDir: string, args: string[]): string {
  try {
    return execFileSync("git", ["-C", resolve(repoDir), ...args], {
      encoding: "utf8",
      timeout: GIT_TIMEOUT_MS,
      maxBuffer: GIT_OUTPUT_LIMIT_BYTES,
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (error) {
    throw new Error(
      `Could not prove dataset checkout with git ${args.join(" ")}: ${message(error)}`,
    );
  }
}

function message(error: unknown): string {
  if (!(error instanceof Error)) return String(error);
  const stderr = "stderr" in error ? String(error.stderr).trim() : "";
  return stderr.length > 0 ? stderr : error.message;
}
