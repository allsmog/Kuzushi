import chalk from "chalk";
import type { Command } from "commander";
import { existsSync } from "node:fs";
import { wrapCliAction, CliUsageError } from "../errors.js";
import { resolveRepo } from "../shared.js";
import {
  defaultDbPath,
  initDb,
  getActionableFindings,
} from "../../store.js";
import type { StoredFindingRecord } from "../../store.js";
import { formatTaintPathForDisplay } from "../../findings/taint-path.js";
import type { Verdict } from "../../types.js";

function colorVerdict(verdict: Verdict): string {
  switch (verdict) {
    case "tp":
      return chalk.red.bold("TRUE POSITIVE");
    case "fp":
      return chalk.green("false positive");
    case "needs_review":
      return chalk.yellow("needs review");
  }
}

function colorSeverity(severity: string): string {
  switch (severity.toUpperCase()) {
    case "ERROR":
    case "CRITICAL":
    case "HIGH":
      return chalk.red(severity);
    case "WARNING":
    case "MEDIUM":
      return chalk.yellow(severity);
    default:
      return chalk.dim(severity);
  }
}

function formatProofStateLabel(proofState: string): string {
  return proofState.replace(/_/g, " ");
}

function section(title: string): void {
  console.log("");
  console.log(chalk.bold(`  ${title}`));
  console.log(chalk.dim(`  ${"─".repeat(title.length + 2)}`));
}

function field(label: string, value: string | number | null | undefined, indent = 4): void {
  if (value == null || value === "") return;
  const pad = " ".repeat(indent);
  console.log(`${pad}${chalk.dim(label + ":")} ${value}`);
}

function findByFingerprint(
  db: ReturnType<typeof initDb>,
  fingerprint: string,
): StoredFindingRecord | undefined {
  // Try exact match first
  const exactResults = getActionableFindings(db, undefined, {
    includeFalsePositives: true,
    fingerprints: [fingerprint],
  });
  if (exactResults.length > 0) {
    return exactResults[0];
  }

  // Try partial match (prefix matching) for truncated fingerprints (8+ chars)
  if (fingerprint.length >= 8) {
    const allFindings = getActionableFindings(db, undefined, {
      includeFalsePositives: true,
    });
    const matches = allFindings.filter((f) =>
      f.fingerprint.startsWith(fingerprint),
    );
    if (matches.length === 1) {
      return matches[0];
    }
    if (matches.length > 1) {
      console.error(
        chalk.yellow(
          `Ambiguous fingerprint prefix "${fingerprint}" matches ${matches.length} findings:`,
        ),
      );
      for (const m of matches.slice(0, 5)) {
        console.error(`  ${chalk.dim(m.fingerprint.slice(0, 16))}... ${m.filePath}:${m.startLine}`);
      }
      if (matches.length > 5) {
        console.error(`  ... and ${matches.length - 5} more`);
      }
      return undefined;
    }
  }

  return undefined;
}

function printFindingDetails(f: StoredFindingRecord): void {
  const verdict = colorVerdict(f.verdict);
  const conf = `${(f.confidence * 100).toFixed(0)}%`;

  console.log("");
  console.log(chalk.bold("─".repeat(60)));
  console.log(chalk.bold("  Finding Details"));
  console.log(chalk.bold("─".repeat(60)));

  // ── Identity ──
  section("Identity");
  field("Fingerprint", f.fingerprint);
  field("Scanner", f.scanner);
  field("Rule ID", f.ruleId);
  field("Location", chalk.cyan(`${f.filePath}:${f.startLine}`));

  // ── Verdict ──
  section("Verdict");
  field("Verdict", verdict);
  field("Confidence", conf);
  field("Severity", colorSeverity(f.severity));

  const verificationBadge =
    f.verifyExploitable === 1
      ? chalk.bgRed.white.bold(" EXPLOITABLE ")
      : f.verifyExploitable === 0
        ? chalk.bgGreen.black(" NOT EXPLOITABLE ")
        : null;
  if (verificationBadge) {
    field("Exploitability", verificationBadge);
  }

  if (f.proofState) {
    field("Proof State", formatProofStateLabel(f.proofState));
  }

  // ── Message ──
  section("Message");
  console.log(`    ${f.message}`);

  // ── Rationale (full, not truncated) ──
  section("Rationale");
  for (const line of f.rationale.split("\n")) {
    console.log(`    ${line}`);
  }

  // ── CWE IDs (from triageDetails if available) ──
  const triageDetails = f.triageDetails;
  if (triageDetails) {
    const cweIds = extractCweIds(triageDetails);
    if (cweIds.length > 0) {
      section("CWE IDs");
      field("CWEs", cweIds.join(", "));
    }
  }

  // ── Verification Details ──
  if (f.verifyExploitable != null) {
    section("Verification");
    field("Exploitable", f.verifyExploitable === 1 ? chalk.red("yes") : chalk.green("no"));
    if (f.verifyPocPayload) {
      field("PoC Payload", f.verifyPocPayload);
    }
    if (f.verifyPocDescription) {
      field("PoC Description", f.verifyPocDescription);
    }
    if (f.verifyAttackVector) {
      field("Attack Vector", f.verifyAttackVector);
    }
    if (f.verifyPreconditions && f.verifyPreconditions.length > 0) {
      field("Preconditions", f.verifyPreconditions.join("; "));
    }
    if (f.verifyConfidence != null) {
      field("Verify Confidence", `${(f.verifyConfidence * 100).toFixed(0)}%`);
    }
    if (f.verifyCostUsd != null && f.verifyCostUsd > 0) {
      field("Verify Cost", `$${f.verifyCostUsd.toFixed(4)}`);
    }
  }

  // ── Taint Path (full, not summarized) ──
  if (f.taintPath && f.taintPath.length > 0) {
    section("Taint Path");
    // Show ALL steps, not truncated
    const taintLines = formatTaintPathForDisplay(f.taintPath, f.taintPath.length);
    for (const line of taintLines) {
      console.log(`    ${line}`);
    }
  }

  // ── Engine Provenance ──
  if (f.engineProvenance && f.engineProvenance.length > 0) {
    section("Engine Provenance");
    for (const entry of f.engineProvenance) {
      console.log(`    ${chalk.dim(entry.kind + ":")} ${entry.detail}`);
    }
  }

  // ── Fix Patch ──
  if (f.fixPatch) {
    section("Fix Patch");
    for (const line of f.fixPatch.split("\n")) {
      console.log(`    ${line}`);
    }
  }

  // ── Verification Steps ──
  if (f.verificationSteps && f.verificationSteps.length > 0) {
    section("Verification Steps");
    for (let i = 0; i < f.verificationSteps.length; i++) {
      console.log(`    ${i + 1}. ${f.verificationSteps[i]}`);
    }
  }

  // ── PoC Harness ──
  if (f.pocHarnessPath || f.pocHarnessSkipped === 1) {
    section("PoC Harness");
    if (f.pocHarnessPath) {
      field("Script Path", chalk.blue(f.pocHarnessPath));
    }
    if (f.pocHarnessLanguage) {
      field("Language", f.pocHarnessLanguage);
    }
    if (f.pocHarnessParsed != null) {
      field("Parsed", f.pocHarnessParsed === 1 ? chalk.green("yes") : chalk.red("no"));
    }
    if (f.pocHarnessParsed === 0 && f.pocHarnessParseError) {
      field("Parse Error", chalk.red(f.pocHarnessParseError));
    }
    if (f.pocHarnessSkipped === 1) {
      field("Skipped", chalk.yellow(f.pocHarnessSkipReason ?? "no reason provided"));
    }
    if (f.pocRunVerdict) {
      const verdictColor =
        f.pocRunVerdict === "PASS" ? chalk.green.bold
          : f.pocRunVerdict === "FAIL" ? chalk.red.bold
            : f.pocRunVerdict === "TIMEOUT" ? chalk.yellow.bold
              : chalk.red;
      field("Execution Result", verdictColor(f.pocRunVerdict));
    }
    if (f.pocRunDurationMs != null) {
      field("Execution Duration", `${(f.pocRunDurationMs / 1000).toFixed(1)}s`);
    }
    if (f.pocRunExitCode != null) {
      field("Exit Code", f.pocRunExitCode);
    }
    if (f.pocHarnessCostUsd != null && f.pocHarnessCostUsd > 0) {
      field("PoC Cost", `$${f.pocHarnessCostUsd.toFixed(4)}`);
    }
  }

  // ── Corroborating Signals ──
  if (f.corroboratingSignals.length > 0) {
    section("Corroborating Signals");
    for (const signal of f.corroboratingSignals) {
      const cweStr = signal.cwe.length > 0 ? ` (${signal.cwe.join(", ")})` : "";
      console.log(
        `    ${chalk.dim(signal.scanner)} ${signal.ruleId} @ ${signal.filePath}:${signal.startLine}${cweStr}`,
      );
    }
  }

  // ── Suppression Reasons ──
  if (f.suppressionReasons.length > 0) {
    section("Suppression Reasons");
    for (const reason of f.suppressionReasons) {
      const penalty = reason.scorePenalty != null ? ` (penalty: ${reason.scorePenalty})` : "";
      console.log(`    ${chalk.dim(`[${reason.kind}]`)} ${reason.id}: ${reason.description}${penalty}`);
    }
  }

  // ── Triage Details (extra info from triageDetailsJson) ──
  if (triageDetails) {
    const hasExtraDetails =
      triageDetails["source"] ||
      triageDetails["sink"] ||
      triageDetails["exploit_scenario"] ||
      triageDetails["recommended_fix"];
    if (hasExtraDetails) {
      section("Triage Details");
      if (triageDetails["source"]) {
        const src = triageDetails["source"] as Record<string, unknown>;
        field("Source Assessment", String(src["why"] ?? ""));
        if (src["evidence"]) field("Source Evidence", String(src["evidence"]));
      }
      if (triageDetails["sink"]) {
        const snk = triageDetails["sink"] as Record<string, unknown>;
        field("Sink Assessment", String(snk["why"] ?? ""));
        if (snk["evidence"]) field("Sink Evidence", String(snk["evidence"]));
      }
      if (triageDetails["exploit_scenario"]) {
        field("Exploit Scenario", String(triageDetails["exploit_scenario"]));
      }
      if (triageDetails["recommended_fix"]) {
        field("Recommended Fix", String(triageDetails["recommended_fix"]));
      }
    }
  }

  // ── Cost Breakdown ──
  const hasAnyCost =
    (f.verifyCostUsd != null && f.verifyCostUsd > 0) ||
    (f.pocHarnessCostUsd != null && f.pocHarnessCostUsd > 0);
  if (hasAnyCost) {
    section("Cost Breakdown");
    if (f.verifyCostUsd != null && f.verifyCostUsd > 0) {
      field("Verification", `$${f.verifyCostUsd.toFixed(4)}`);
    }
    if (f.pocHarnessCostUsd != null && f.pocHarnessCostUsd > 0) {
      field("PoC Harness", `$${f.pocHarnessCostUsd.toFixed(4)}`);
    }
  }

  // ── Metadata ──
  if (f.findingMetadata) {
    const meta = f.findingMetadata;
    const hasMetadata =
      meta.latestDynamicRunId ||
      meta.latestPatchRunId ||
      meta.latestDynamicStatus ||
      (meta.notes && meta.notes.length > 0);
    if (hasMetadata) {
      section("Metadata");
      if (meta.latestDynamicStatus) {
        field("Dynamic Status", meta.latestDynamicStatus);
      }
      if (meta.latestDynamicRunId) {
        field("Dynamic Run ID", meta.latestDynamicRunId);
      }
      if (meta.latestPatchRunId) {
        field("Patch Run ID", meta.latestPatchRunId);
      }
      if (meta.notes && meta.notes.length > 0) {
        for (const note of meta.notes) {
          console.log(`    ${chalk.dim("Note:")} ${note}`);
        }
      }
    }
  }

  console.log("");
  console.log(chalk.bold("─".repeat(60)));
}

/**
 * Extract CWE IDs from the triageDetails record.
 * The triage details may contain CWE references in various forms.
 */
function extractCweIds(details: Record<string, unknown>): string[] {
  // Check for explicit cwe field
  if (Array.isArray(details["cwe"])) {
    return details["cwe"].map((v) => String(v)).filter(Boolean);
  }
  return [];
}

export function registerExplainCommand(program: Command): void {
  program
    .command("explain")
    .description("Show full details for a finding by fingerprint")
    .argument("<fingerprint>", "Finding fingerprint (full or 8+ character prefix)")
    .option("-r, --repo <path>", "Repository path (used to locate DB)", ".")
    .option("--db <path>", "SQLite database path (default: <repo>/.kuzushi/findings.sqlite3)")
    .action(
      wrapCliAction(
        async (fingerprint: string, opts: { repo: string; db?: string }) => {
          const { root } = resolveRepo(opts.repo);
          const dbPath = opts.db ?? defaultDbPath(root);

          if (!existsSync(dbPath)) {
            throw new CliUsageError(
              `Database not found at ${dbPath}. Run a scan first or specify --db.`,
            );
          }

          const db = initDb(dbPath);
          try {
            const finding = findByFingerprint(db, fingerprint);
            if (!finding) {
              throw new CliUsageError(
                `No finding found matching fingerprint "${fingerprint}".`,
              );
            }
            printFindingDetails(finding);
          } finally {
            db.close();
          }
        },
      ),
    );
}
