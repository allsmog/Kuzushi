import chalk from "chalk";
import { writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
import type Database from "better-sqlite3";
import { getActionableFindings, type StoredFindingRecord } from "../store.js";
import { generateHtmlReport } from "../report-html.js";
import { formatTaintPathForDisplay, summarizeTaintPath } from "../findings/taint-path.js";
import type { Verdict } from "../types.js";

function colorVerdict(verdict: Verdict): string {
  switch (verdict) {
    case "tp":
      return chalk.red.bold("TP");
    case "fp":
      return chalk.green("FP");
    case "needs_review":
      return chalk.yellow("REVIEW");
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

function printFindingList(findings: StoredFindingRecord[]): void {
  if (findings.length === 0) {
    console.log(chalk.dim("  No findings to display."));
    return;
  }
  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    const num = chalk.bold(`#${i + 1}`);
    const verdict = colorVerdict(f.verdict);
    const severity = colorSeverity(f.severity);
    const location = chalk.cyan(`${f.filePath}:${f.startLine}`);
    const scanner = chalk.dim(`[${f.scanner}]`);
    console.log(`  ${num}  ${verdict}  ${severity}  ${scanner}  ${location}`);
  }
}

function printFindingDetails(f: StoredFindingRecord, index: number): void {
  console.log("");
  console.log(chalk.bold("─".repeat(60)));
  console.log(chalk.bold(`  Finding #${index}`));
  console.log(chalk.bold("─".repeat(60)));

  // Identity
  console.log("");
  console.log(`  ${chalk.dim("Fingerprint:")} ${f.fingerprint}`);
  console.log(`  ${chalk.dim("Scanner:")}     ${f.scanner}`);
  console.log(`  ${chalk.dim("Rule ID:")}     ${f.ruleId}`);
  console.log(`  ${chalk.dim("Location:")}    ${chalk.cyan(`${f.filePath}:${f.startLine}`)}`);

  // Verdict
  console.log("");
  const verdictLabel =
    f.verdict === "tp"
      ? chalk.red.bold("TRUE POSITIVE")
      : f.verdict === "fp"
        ? chalk.green("false positive")
        : chalk.yellow("needs review");
  console.log(`  ${chalk.dim("Verdict:")}     ${verdictLabel}`);
  console.log(`  ${chalk.dim("Confidence:")}  ${(f.confidence * 100).toFixed(0)}%`);
  console.log(`  ${chalk.dim("Severity:")}    ${colorSeverity(f.severity)}`);

  if (f.verifyExploitable === 1) {
    console.log(`  ${chalk.dim("Exploitable:")} ${chalk.bgRed.white.bold(" EXPLOITABLE ")}`);
  } else if (f.verifyExploitable === 0) {
    console.log(`  ${chalk.dim("Exploitable:")} ${chalk.bgGreen.black(" NOT EXPLOITABLE ")}`);
  }

  if (f.proofState) {
    console.log(`  ${chalk.dim("Proof State:")} ${f.proofState.replace(/_/g, " ")}`);
  }

  // Message
  console.log("");
  console.log(`  ${chalk.dim("Message:")}`);
  console.log(`    ${f.message}`);

  // Rationale (full, untruncated)
  console.log("");
  console.log(`  ${chalk.dim("Rationale:")}`);
  for (const line of f.rationale.split("\n")) {
    console.log(`    ${line}`);
  }

  // Verification details
  if (f.verifyExploitable != null) {
    console.log("");
    console.log(`  ${chalk.dim("Verification:")}`);
    if (f.verifyPocPayload) {
      console.log(`    ${chalk.dim("PoC Payload:")} ${f.verifyPocPayload}`);
    }
    if (f.verifyPocDescription) {
      console.log(`    ${chalk.dim("PoC Description:")} ${f.verifyPocDescription}`);
    }
    if (f.verifyAttackVector) {
      console.log(`    ${chalk.dim("Attack Vector:")} ${f.verifyAttackVector}`);
    }
    if (f.verifyPreconditions && f.verifyPreconditions.length > 0) {
      console.log(`    ${chalk.dim("Preconditions:")} ${f.verifyPreconditions.join("; ")}`);
    }
    if (f.verifyConfidence != null) {
      console.log(`    ${chalk.dim("Verify Confidence:")} ${(f.verifyConfidence * 100).toFixed(0)}%`);
    }
    if (f.verifyCostUsd != null && f.verifyCostUsd > 0) {
      console.log(`    ${chalk.dim("Verify Cost:")} $${f.verifyCostUsd.toFixed(4)}`);
    }
  }

  // Taint path
  if (f.taintPath && f.taintPath.length > 0) {
    console.log("");
    console.log(`  ${chalk.dim("Taint Path:")}`);
    const summary = summarizeTaintPath(f.taintPath);
    if (summary) {
      console.log(`    ${summary}`);
    }
    const taintLines = formatTaintPathForDisplay(f.taintPath, f.taintPath.length);
    for (const line of taintLines) {
      console.log(`    ${line}`);
    }
  }

  // Engine provenance
  if (f.engineProvenance && f.engineProvenance.length > 0) {
    console.log("");
    console.log(`  ${chalk.dim("Engine Provenance:")}`);
    for (const entry of f.engineProvenance) {
      console.log(`    ${chalk.dim(entry.kind + ":")} ${entry.detail}`);
    }
  }

  // Fix patch
  if (f.fixPatch) {
    console.log("");
    console.log(`  ${chalk.dim("Fix Patch:")}`);
    for (const line of f.fixPatch.split("\n")) {
      console.log(`    ${line}`);
    }
  }

  // Verification steps
  if (f.verificationSteps && f.verificationSteps.length > 0) {
    console.log("");
    console.log(`  ${chalk.dim("Verification Steps:")}`);
    for (let i = 0; i < f.verificationSteps.length; i++) {
      console.log(`    ${i + 1}. ${f.verificationSteps[i]}`);
    }
  }

  // PoC harness
  if (f.pocHarnessPath || f.pocHarnessSkipped === 1) {
    console.log("");
    console.log(`  ${chalk.dim("PoC Harness:")}`);
    if (f.pocHarnessPath) {
      console.log(`    ${chalk.dim("Script:")} ${chalk.blue(f.pocHarnessPath)}`);
    }
    if (f.pocRunVerdict) {
      const verdictColor =
        f.pocRunVerdict === "PASS" ? chalk.green.bold
          : f.pocRunVerdict === "FAIL" ? chalk.red.bold
            : f.pocRunVerdict === "TIMEOUT" ? chalk.yellow.bold
              : chalk.red;
      console.log(`    ${chalk.dim("Execution:")} ${verdictColor(f.pocRunVerdict)}`);
    }
    if (f.pocHarnessSkipped === 1) {
      console.log(`    ${chalk.yellow("Skipped:")} ${f.pocHarnessSkipReason ?? "no reason provided"}`);
    }
  }

  // Corroborating signals
  if (f.corroboratingSignals.length > 0) {
    console.log("");
    console.log(`  ${chalk.dim("Corroborating Signals:")}`);
    for (const signal of f.corroboratingSignals) {
      const cweStr = signal.cwe.length > 0 ? ` (${signal.cwe.join(", ")})` : "";
      console.log(
        `    ${chalk.dim(signal.scanner)} ${signal.ruleId} @ ${signal.filePath}:${signal.startLine}${cweStr}`,
      );
    }
  }

  // Suppression reasons
  if (f.suppressionReasons.length > 0) {
    console.log("");
    console.log(`  ${chalk.dim("Suppression Reasons:")}`);
    for (const reason of f.suppressionReasons) {
      const penalty = reason.scorePenalty != null ? ` (penalty: ${reason.scorePenalty})` : "";
      console.log(`    ${chalk.dim(`[${reason.kind}]`)} ${reason.id}: ${reason.description}${penalty}`);
    }
  }

  console.log("");
  console.log(chalk.bold("─".repeat(60)));
}

export async function startInteractiveRepl(db: Database.Database, repo: string): Promise<void> {
  const allFindings = getActionableFindings(db, repo, { includeFalsePositives: true });

  if (allFindings.length === 0) {
    return;
  }

  let currentFindings = allFindings;
  let currentFilter: string | null = null;

  const counts: Record<Verdict, number> = { tp: 0, fp: 0, needs_review: 0 };
  for (const f of allFindings) {
    counts[f.verdict]++;
  }

  console.log("");
  console.log(
    `${allFindings.length} findings (${counts.tp} TP, ${counts.needs_review} needs_review, ${counts.fp} FP). Commands:`,
  );
  console.log(`  ${chalk.bold("explain <n>")}    Deep-dive into finding #n`);
  console.log(`  ${chalk.bold("patch <n>")}      Show fingerprint for kuzushi patch`);
  console.log(`  ${chalk.bold("list")}           Re-list findings`);
  console.log(`  ${chalk.bold("filter <type>")}  Filter by tp/fp/needs_review`);
  console.log(`  ${chalk.bold("export html")}    Save HTML report`);
  console.log(`  ${chalk.bold("q")}              Quit`);
  console.log("");

  printFindingList(currentFindings);
  console.log("");

  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: chalk.cyan("kuzushi> "),
  });

  return new Promise<void>((resolve) => {
    rl.prompt();

    rl.on("line", (line) => {
      const input = line.trim();
      if (!input) {
        rl.prompt();
        return;
      }

      const parts = input.split(/\s+/);
      const cmd = parts[0].toLowerCase();
      const arg = parts[1];

      switch (cmd) {
        case "q":
        case "quit":
        case "exit": {
          rl.close();
          return;
        }

        case "list": {
          if (currentFilter) {
            console.log(chalk.dim(`  (filtered: ${currentFilter})`));
          }
          printFindingList(currentFindings);
          console.log("");
          break;
        }

        case "filter": {
          if (!arg) {
            console.log(chalk.yellow("  Usage: filter <tp|fp|needs_review>"));
            console.log(chalk.dim("  Use 'filter clear' to remove filter."));
            break;
          }
          const filterType = arg.toLowerCase();
          if (filterType === "clear" || filterType === "all") {
            currentFindings = allFindings;
            currentFilter = null;
            console.log(chalk.dim("  Filter cleared."));
            printFindingList(currentFindings);
            console.log("");
          } else if (filterType === "tp" || filterType === "fp" || filterType === "needs_review") {
            currentFindings = allFindings.filter((f) => f.verdict === filterType);
            currentFilter = filterType;
            console.log(chalk.dim(`  Showing ${currentFindings.length} ${filterType} findings.`));
            printFindingList(currentFindings);
            console.log("");
          } else {
            console.log(chalk.yellow(`  Unknown filter type: ${arg}`));
            console.log(chalk.dim("  Valid types: tp, fp, needs_review, clear"));
          }
          break;
        }

        case "explain": {
          if (!arg) {
            console.log(chalk.yellow("  Usage: explain <n>"));
            break;
          }
          const explainIdx = parseInt(arg, 10);
          if (isNaN(explainIdx) || explainIdx < 1 || explainIdx > currentFindings.length) {
            console.log(chalk.yellow(`  Invalid finding number. Use 1-${currentFindings.length}.`));
            break;
          }
          printFindingDetails(currentFindings[explainIdx - 1], explainIdx);
          break;
        }

        case "patch": {
          if (!arg) {
            console.log(chalk.yellow("  Usage: patch <n>"));
            break;
          }
          const patchIdx = parseInt(arg, 10);
          if (isNaN(patchIdx) || patchIdx < 1 || patchIdx > currentFindings.length) {
            console.log(chalk.yellow(`  Invalid finding number. Use 1-${currentFindings.length}.`));
            break;
          }
          const finding = currentFindings[patchIdx - 1];
          console.log("");
          console.log(`  ${chalk.bold("Run:")}`);
          console.log(`    kuzushi patch ${repo} --fingerprint ${finding.fingerprint}`);
          console.log("");
          break;
        }

        case "export": {
          if (arg === "html") {
            const outputPath = "kuzushi-report.html";
            try {
              const html = generateHtmlReport(db, repo);
              writeFileSync(outputPath, html, "utf-8");
              console.log(`  ${chalk.green("HTML report written to")} ${outputPath}`);
            } catch (err) {
              console.log(chalk.red(`  Failed to generate HTML report: ${err}`));
            }
          } else {
            console.log(chalk.yellow("  Usage: export html"));
          }
          break;
        }

        default: {
          console.log(chalk.yellow(`  Unknown command: ${cmd}`));
          console.log(chalk.dim("  Commands: explain <n>, patch <n>, list, filter <type>, export html, q"));
        }
      }

      rl.prompt();
    });

    rl.on("close", () => {
      resolve();
    });
  });
}
