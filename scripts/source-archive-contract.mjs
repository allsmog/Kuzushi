import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync } from "node:fs";
import path from "node:path";
import { gunzipSync } from "node:zlib";

const fullShaPattern = /^[0-9a-f]{40}$/;
const generatedStatePattern = /(^|\/)\.kuzushi(?:\/|$)/;
const ignoreSentinelPattern = /(^|\/)\.kuzushi\/\.gitignore$/;
const sourceArchivePathspecs = [".", ":(exclude,glob).kuzushi/**", ":(exclude,glob)**/.kuzushi/**"];

export function trackedGeneratedStateFailures(paths) {
  return paths
    .filter((file) => generatedStatePattern.test(file) && !ignoreSentinelPattern.test(file))
    .map((file) => `tracked generated state is forbidden: ${file}`);
}

export function trackedPathsAtCommit(repo, commitSha) {
  const output = runGit(repo, ["ls-tree", "-r", "--name-only", "-z", commitSha]);
  return output.toString("utf8").split("\0").filter(Boolean);
}

export function assertCleanTrackedState(repo, commitSha) {
  const resolvedSha = resolveExactCommit(repo, commitSha);
  const failures = trackedGeneratedStateFailures(trackedPathsAtCommit(repo, resolvedSha));
  if (failures.length > 0) throw new Error(formatTrackedStateFailures(failures));
  return resolvedSha;
}

export function createSourceArchive({ repo, commitSha, output }) {
  const resolvedSha = assertCleanTrackedState(repo, commitSha);
  const destination = path.resolve(output);
  if (existsSync(destination)) throw new Error(`source archive already exists: ${destination}`);
  mkdirSync(path.dirname(destination), { recursive: true });
  const temporary = `${destination}.tmp-${process.pid}-${Date.now()}`;
  try {
    runGit(repo, archiveArgs("tar.gz", resolvedSha, temporary));
    const receipt = verifySourceArchive(repo, resolvedSha, temporary);
    renameSync(temporary, destination);
    return { ...receipt, file: path.basename(destination) };
  } finally {
    rmSync(temporary, { force: true });
  }
}

export function verifySourceArchive(repo, commitSha, archivePath) {
  const tarBytes = gunzipSync(readFileSync(archivePath));
  const embeddedSha = runGit(repo, ["get-tar-commit-id"], tarBytes).toString("utf8").trim();
  if (embeddedSha !== commitSha)
    throw new Error(`source archive embeds ${embeddedSha}, not ${commitSha}`);
  const actual = tarPaths(tarBytes);
  const expected = tarPaths(runGit(repo, archiveArgs("tar", commitSha)));
  assertCompleteArchive(actual, expected);
  return {
    commitSha,
    size: statSync(archivePath).size,
    sha256: fileSha256(archivePath),
    entries: actual.length,
  };
}

export function fileSha256(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function resolveExactCommit(repo, commitSha) {
  if (!fullShaPattern.test(commitSha))
    throw new Error("source commit must be a lowercase full SHA");
  const resolved = runGit(repo, ["rev-parse", "--verify", `${commitSha}^{commit}`])
    .toString("utf8")
    .trim();
  if (resolved !== commitSha)
    throw new Error(`source commit resolved to ${resolved}, not ${commitSha}`);
  return resolved;
}

function tarPaths(tarBytes) {
  const result = spawnSync("tar", ["-tf", "-"], {
    input: tarBytes,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  assertSucceeded("tar -tf", result);
  return result.stdout.split(/\r?\n/).filter(Boolean);
}

function assertCompleteArchive(actual, expected) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error("source archive inventory does not match the exact commit export");
  }
  if (!actual.includes("package.json")) throw new Error("source archive is missing package.json");
  const unsafe = actual.map((file) => file.replace(/\/$/, "")).filter(unsafeArchivePath);
  if (unsafe.length > 0) throw new Error(`source archive contains unsafe path ${unsafe[0]}`);
}

function unsafeArchivePath(file) {
  return (
    file.startsWith("/") ||
    file.includes("\\") ||
    file.split("/").some((segment) => segment === ".." || segment === ".kuzushi")
  );
}

function archiveArgs(format, commitSha, output) {
  const options = [`--format=${format}`];
  if (output) options.push("--output", output);
  return ["archive", ...options, commitSha, "--", ...sourceArchivePathspecs];
}

function formatTrackedStateFailures(failures) {
  const shown = failures.slice(0, 20);
  const omitted = failures.length - shown.length;
  return [...shown, ...(omitted > 0 ? [`... and ${omitted} more tracked state files`] : [])].join(
    "\n",
  );
}

function runGit(repo, args, input) {
  const result = spawnSync("git", args, {
    cwd: repo,
    input,
    encoding: input ? undefined : "buffer",
    maxBuffer: 512 * 1024 * 1024,
  });
  assertSucceeded(`git ${args.join(" ")}`, result);
  return result.stdout;
}

function assertSucceeded(command, result) {
  if (!result.error && result.status === 0) return;
  const detail = [result.stdout, result.stderr].filter(Boolean).join("\n").trim();
  throw result.error ?? new Error(`${command} failed: ${detail}`);
}
