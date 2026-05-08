/**
 * JUnit XML report writer.
 *
 * Emits a <testsuite> per scanned module (or one global suite if no modules),
 * with one <testcase> per finding. CI platforms (GitHub Actions test report
 * view, GitLab, CircleCI, Buildkite) render these natively so security
 * findings land in the "Tests" tab alongside unit tests. Verdicts map to
 * test outcomes:
 *
 *   tp / exploitable   → <failure>   (visible, red)
 *   needs_review       → <failure>   (visible, red)
 *   by_design          → <skipped>   (visible, grey)
 *   fp                 → (omitted — suppresses noise)
 *   unset              → <failure>   (visible — treat as actionable by default)
 *
 * The schema follows the de-facto JUnit XML convention used by most
 * consumers (Jenkins, GitHub Actions, Bitbucket, etc).
 */

import type Database from "better-sqlite3";
import type { PipelineStats } from "./bus/events.js";
import { getActionableFindings } from "./store.js";

export interface JunitReportOptions {
  repo: string;
  stats: Partial<PipelineStats>;
  runId: string;
  repoRoot?: string;
  fingerprints?: string[];
}

export function generateJunitReport(db: Database.Database, opts: JunitReportOptions): string {
  const findings = getActionableFindings(db, opts.repo, {
    includeFalsePositives: false,
    fingerprints: opts.fingerprints,
  });

  // Group findings by taskId — each task becomes a <testsuite>.
  const suites = new Map<string, typeof findings>();
  for (const f of findings) {
    const key = f.taskId ?? "unknown";
    const bucket = suites.get(key) ?? [];
    bucket.push(f);
    suites.set(key, bucket);
  }

  const totalTests = findings.length;
  const totalFailures = findings.filter((f) => f.verdict !== "by_design").length;
  const totalSkipped = findings.filter((f) => f.verdict === "by_design").length;
  const totalCostUsd = opts.stats.totalCostUsd ?? 0;
  const timestamp = new Date().toISOString();

  const lines: string[] = [];
  lines.push('<?xml version="1.0" encoding="UTF-8"?>');
  lines.push(
    `<testsuites name="kuzushi" tests="${totalTests}" failures="${totalFailures}" skipped="${totalSkipped}" time="${totalCostUsd.toFixed(4)}">`,
  );

  if (suites.size === 0) {
    // No findings — emit an empty suite so CI still renders something useful.
    lines.push(
      `  <testsuite name="${escapeXmlAttr(opts.repo)}" tests="0" failures="0" skipped="0" timestamp="${timestamp}"/>`,
    );
  } else {
    for (const [taskId, taskFindings] of suites) {
      const suiteFailures = taskFindings.filter((f) => f.verdict !== "by_design").length;
      const suiteSkipped = taskFindings.filter((f) => f.verdict === "by_design").length;
      lines.push(
        `  <testsuite name="${escapeXmlAttr(`${opts.repo}/${taskId}`)}" tests="${taskFindings.length}" failures="${suiteFailures}" skipped="${suiteSkipped}" timestamp="${timestamp}">`,
      );
      for (const f of taskFindings) {
        const name = `${f.ruleId ?? "finding"}@${f.filePath}:${f.startLine}`;
        const classname = `${taskId}.${(f.ruleId ?? "finding").replace(/[^A-Za-z0-9._-]/g, "_")}`;
        lines.push(
          `    <testcase name="${escapeXmlAttr(name)}" classname="${escapeXmlAttr(classname)}">`,
        );
        if (f.verdict === "by_design") {
          lines.push(
            `      <skipped message="${escapeXmlAttr(`${f.severity ?? ""}: ${f.message ?? ""}`.trim())}"/>`,
          );
        } else {
          const failureType = deriveFailureType(f.verdict ?? "unset", Boolean(f.verifyExploitable));
          const short = `${f.severity ?? "ERROR"}: ${f.message ?? f.ruleId ?? "finding"}`;
          const body = [
            `File:        ${f.filePath}:${f.startLine}`,
            `Rule:        ${f.ruleId ?? "n/a"}`,
            `Severity:    ${f.severity ?? "n/a"}`,
            `Verdict:     ${f.verdict ?? "unset"}`,
            f.verifyExploitable === 1 ? "Exploitable: confirmed" : "",
            f.rationale ? `Rationale:   ${String(f.rationale).slice(0, 1000)}` : "",
            `Fingerprint: ${f.fingerprint}`,
          ]
            .filter(Boolean)
            .join("\n");
          lines.push(
            `      <failure type="${escapeXmlAttr(failureType)}" message="${escapeXmlAttr(short)}"><![CDATA[\n${escapeCdata(body)}\n]]></failure>`,
          );
        }
        lines.push(`    </testcase>`);
      }
      lines.push(`  </testsuite>`);
    }
  }

  lines.push(`</testsuites>`);
  return `${lines.join("\n")}\n`;
}

function deriveFailureType(verdict: string, exploitable: boolean): string {
  if (exploitable) return "security.exploitable";
  if (verdict === "tp") return "security.true-positive";
  if (verdict === "needs_review") return "security.needs-review";
  return "security.finding";
}

function escapeXmlAttr(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\n/g, " ")
    .replace(/\r/g, " ");
}

function escapeCdata(value: string): string {
  // CDATA cannot contain "]]>" — split it.
  return value.replace(/]]>/g, "]]]]><![CDATA[>");
}
