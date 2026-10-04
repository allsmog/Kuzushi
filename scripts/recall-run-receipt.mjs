import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const digest = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const save = (path, value) => writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
const git = (target, ...args) =>
  execFileSync("git", ["-C", target, ...args], { encoding: "utf8" }).trim();

export function targetIdentity(target, oraclePath, scopePath) {
  const oracle = readJson(oraclePath);
  const commit = git(target, "rev-parse", "HEAD");
  validateCommit(commit, oracle.commit);
  execFileSync("git", ["-C", target, "diff", "--exit-code", "HEAD", "--"], { stdio: "pipe" });
  const extra = git(target, "ls-files", "--others", "--exclude-standard", "-z")
    .split("\0")
    .filter(Boolean);
  if (extra.some((name) => !allowedStateFile(name)))
    throw Error("target contains untracked source files");
  return {
    target: resolve(target),
    commit,
    tree: git(target, "rev-parse", "HEAD^{tree}"),
    oracleSha256: digest(oraclePath),
    scopeSha256: digest(scopePath),
  };
}

function validateCommit(commit, expected) {
  if (!/^[0-9a-f]{40}$/.test(expected ?? ""))
    throw Error("official benchmark requires a full pinned oracle commit");
  if (commit !== expected) throw Error("target commit does not match the oracle");
}

function allowedStateFile(name) {
  return name === ".kuzushi-slice.toml" || name.startsWith(".kuzushi/");
}

export function findingsFromScan(scan, sarif) {
  validateScanStatus(scan);
  if (!scan.runId || sarif.properties?.kuzushiScanRunId !== scan.runId)
    throw Error("SARIF is not bound to this exact scan run");
  if (!Array.isArray(sarif.runs)) throw Error("SARIF has no runs");
  const findings = sarif.runs.flatMap((run) =>
    run.results.map((result) => findingRow(run, result)),
  );
  const metadata = sarif.properties?.kuzushiExport;
  if (
    metadata?.completeness !== "all" ||
    metadata.totalCount !== findings.length ||
    metadata.includedCount !== findings.length
  ) {
    throw Error("SARIF export is incomplete");
  }
  return { run_id: scan.runId, complete: true, count: findings.length, findings };
}

function validateScanStatus(scan) {
  if (scan.ok !== true || ["partial", "failed", "canceled", "interrupted"].includes(scan.status)) {
    throw Error("scan did not complete successfully");
  }
}

function findingRow(run, result) {
  const location = result.locations?.[0]?.physicalLocation;
  const props = result.properties ?? {};
  const uri = location?.artifactLocation?.uri;
  if (!uri || !result.fingerprints?.["kuzushi/v1"])
    throw Error("SARIF finding has no location or fingerprint");
  const file = uri.startsWith("file:") ? fileURLToPath(uri) : decodeURIComponent(uri);
  return {
    fingerprint: result.fingerprints["kuzushi/v1"],
    rule_id: result.ruleId,
    severity: props.kuzushiSeverity ?? result.level,
    file_path: file,
    start_line: location.region?.startLine ?? 0,
    title: result.ruleId,
    message: `${result.message?.text ?? ""} ${props.kuzushiCwe ?? ""}`,
    tool: run.tool.driver.name,
    vuln_source: props.kuzushiVulnSource ?? null,
    static_proof_state: props.kuzushiStaticProofState ?? null,
    verdict: props.kuzushiTriageVerdict ?? null,
  };
}

export function scanCost(scan) {
  const complete = scan.providerSpendUnresolved === false;
  const exact = complete && Number.isFinite(scan.costUsd) && scan.costUsd >= 0;
  return {
    exactUsd: exact ? scan.costUsd : null,
    observedUsd: scan.observedCostUsd ?? null,
    estimatedUsd: scan.estimatedCostUsd ?? null,
    complete,
    source: "exact-scan-receipt",
  };
}

function prepare(target, oracle, scope, receipt) {
  save(receipt, {
    schemaVersion: 1,
    status: "prepared",
    identity: targetIdentity(target, oracle, scope),
  });
}

function complete(target, oracle, scope, receipt, scanPath, sarifPath, findingsPath) {
  const previous = readJson(receipt);
  const identity = targetIdentity(target, oracle, scope);
  if (JSON.stringify(previous.identity) !== JSON.stringify(identity))
    throw Error("benchmark target or oracle changed during the scan");
  const scan = readJson(scanPath);
  const findings = findingsFromScan(scan, readJson(sarifPath));
  save(findingsPath, findings);
  save(receipt, {
    ...previous,
    status: "valid",
    runId: scan.runId,
    cost: scanCost(scan),
    storage: scan.db,
    engineCoverage: scan.whiteboxStatic,
    scanSha256: digest(scanPath),
    sarifSha256: digest(sarifPath),
    findingsSha256: digest(findingsPath),
  });
}

export function verifyScoreBundle(directory) {
  const receipt = readJson(`${directory}/validity.json`);
  if (receipt.status !== "valid") throw Error(`invalid benchmark bundle: ${receipt.status}`);
  verifyBundleDigests(directory, receipt);
  verifyScoreThreshold(readJson(`${directory}/match.json`));
}

function verifyBundleDigests(directory, receipt) {
  if (receipt.findingsSha256 !== digest(`${directory}/findings.json`))
    throw Error("findings changed after validation");
  if (receipt.scanSha256 !== digest(`${directory}/scan.json`))
    throw Error("scan receipt changed after validation");
}

function verifyScoreThreshold(score) {
  if (!Number.isFinite(score.expected_min_recall))
    throw Error("benchmark score has no recall threshold");
  if (!Number.isFinite(score.recall?.pm_lines))
    throw Error("benchmark score has no measured recall");
  if (score.recall.pm_lines < score.expected_min_recall)
    throw Error("benchmark recall threshold failed");
}

function main(args) {
  const [mode, ...rest] = args;
  if (mode === "prepare") return prepare(...rest);
  if (mode === "complete") return complete(...rest);
  if (mode === "verify") return verifyScoreBundle(rest[0]);
  throw Error("expected prepare, complete, or verify");
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
