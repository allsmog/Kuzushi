import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { createSourceArchive, trackedGeneratedStateFailures } from "./source-archive-contract.mjs";

test("tracked generated state is rejected at any repository depth", () => {
  assert.deepEqual(trackedGeneratedStateFailures(["src/lib.rs"]), []);
  assert.deepEqual(trackedGeneratedStateFailures(["crate/.kuzushi/.gitignore"]), []);
  assert.equal(trackedGeneratedStateFailures(["crate/.kuzushi/v3/latest"]).length, 1);
});

test("source export is complete, commit-bound, export-aware, and atomic", () => {
  const repo = fixtureRepository();
  writeFileSync(path.join(repo, ".gitattributes"), "private/ export-ignore\n");
  writeFileSync(path.join(repo, "package.json"), "{}\n");
  mkdirSync(path.join(repo, "src"));
  writeFileSync(path.join(repo, "src", "lib.rs"), "pub fn ready() {}\n");
  writeFileSync(path.join(repo, "src", "large.bin"), randomBytes(2 * 1024 * 1024));
  mkdirSync(path.join(repo, "private"));
  writeFileSync(path.join(repo, "private", "note.txt"), "not exported\n");
  mkdirSync(path.join(repo, "crate", ".kuzushi"), { recursive: true });
  writeFileSync(path.join(repo, "crate", ".kuzushi", ".gitignore"), "*\n!.gitignore\n");
  commitAll(repo);
  const sha = git(repo, ["rev-parse", "HEAD"]).trim();
  const output = path.join(repo, "candidate", "source.tar.gz");
  const receipt = createSourceArchive({ repo, commitSha: sha, output });
  assert.equal(receipt.commitSha, sha);
  assert.match(receipt.sha256, /^[0-9a-f]{64}$/);
  const listing = execFileSync("tar", ["-tzf", output], { encoding: "utf8" });
  assert.match(listing, /^package\.json$/m);
  assert.match(listing, /^src\/lib\.rs$/m);
  assert.doesNotMatch(listing, /private\/note\.txt/);
  assert.doesNotMatch(listing, /\.kuzushi/);
});

test("source export fails before writing when generated state is tracked", () => {
  const repo = fixtureRepository();
  writeFileSync(path.join(repo, "package.json"), "{}\n");
  mkdirSync(path.join(repo, ".kuzushi"));
  writeFileSync(path.join(repo, ".kuzushi", "latest"), "run-1\n");
  commitAll(repo);
  const sha = git(repo, ["rev-parse", "HEAD"]).trim();
  assert.throws(
    () => createSourceArchive({ repo, commitSha: sha, output: path.join(repo, "source.tgz") }),
    /tracked generated state/,
  );
});

function fixtureRepository() {
  const repo = mkdtempSync(path.join(tmpdir(), "kuzushi-source-contract-"));
  git(repo, ["init", "--quiet"]);
  git(repo, ["config", "user.name", "Release Test"]);
  git(repo, ["config", "user.email", "release-test@example.invalid"]);
  return repo;
}

function commitAll(repo) {
  git(repo, ["add", "."]);
  git(repo, ["commit", "--quiet", "-m", "fixture"]);
}

function git(repo, args) {
  return execFileSync("git", args, { cwd: repo, encoding: "utf8" });
}
