/**
 * Finding export action menu — shown after pipeline or review completes.
 *
 * Offers one-keypress export options:
 *   [c] Copy findings to clipboard (markdown)
 *   [g] Generate GitHub issue template
 *   [j] Export as Jira CSV
 *   [enter] done
 */
import React, { useState } from "react";
import { Box, Text, useInput, useApp } from "ink";
import chalk from "chalk";
import { icons } from "../icons.js";
import { boxHeader, boxFooter } from "../format.js";
import type { ActionableFinding } from "../state.js";

interface ExportActionsProps {
  findings: ActionableFinding[];
  repoName: string;
  onDone: () => void;
}

export function ExportActions({ findings, repoName, onDone }: ExportActionsProps): React.ReactElement {
  const { exit } = useApp();
  const [status, setStatus] = useState<string | null>(null);

  const actionableCount = findings.filter((f) => f.verdict !== "fp").length;

  useInput((input, key) => {
    if (key.return || key.escape) {
      onDone();
      exit();
      return;
    }

    if (input === "c") {
      const markdown = generateMarkdownExport(findings, repoName);
      copyToClipboard(markdown);
      setStatus(`${icons.success} Copied ${actionableCount} findings to clipboard as markdown`);
    } else if (input === "g") {
      const template = generateGitHubIssueTemplate(findings, repoName);
      copyToClipboard(template);
      setStatus(`${icons.success} GitHub issue template copied to clipboard`);
    } else if (input === "j") {
      const csv = generateJiraCsv(findings);
      copyToClipboard(csv);
      setStatus(`${icons.success} Jira CSV copied to clipboard (${actionableCount} rows)`);
    }
  });

  return (
    <Box flexDirection="column">
      <Text>{""}</Text>
      <Text>{boxHeader("Export", 58)}</Text>
      <Text>{""}</Text>
      <Text>{"  "}{chalk.dim(`${actionableCount} actionable findings available`)}</Text>
      <Text>{""}</Text>
      <Text>{"  "}{chalk.redBright.bold("[c]")} Copy to clipboard {chalk.dim("(markdown)")}</Text>
      <Text>{"  "}{chalk.white.bold("[g]")} GitHub issue template</Text>
      <Text>{"  "}{chalk.blue.bold("[j]")} Jira CSV export</Text>
      <Text>{"  "}{chalk.dim("[enter] done")}</Text>

      {status && (
        <>
          <Text>{""}</Text>
          <Text>{"  "}{chalk.green(status)}</Text>
        </>
      )}

      <Text>{""}</Text>
      <Text>{boxFooter(58)}</Text>
    </Box>
  );
}

function generateMarkdownExport(findings: ActionableFinding[], repoName: string): string {
  const actionable = findings.filter((f) => f.verdict !== "fp");
  const lines = [
    `# Security Findings — ${repoName}`,
    "",
    `**${actionable.length} actionable findings**`,
    "",
  ];

  for (const f of actionable) {
    const severity = f.severity === "ERROR" ? "🔴" : "🟡";
    const verdict = f.verdict === "tp" ? "TRUE POSITIVE" : f.verdict === "needs_review" ? "NEEDS REVIEW" : f.verdict.toUpperCase();
    const exploitable = f.verifyExploitable === 1 ? " **EXPLOITABLE**" : "";

    lines.push(`### ${severity} ${verdict} — ${f.ruleId}${exploitable}`);
    lines.push(`**Location:** \`${f.filePath}:${f.startLine}\``);
    lines.push(`**Scanner:** ${f.taskId} | **Confidence:** ${(f.confidence * 100).toFixed(0)}%`);
    lines.push("");
    lines.push(f.rationale);
    if (f.verifyPocPayload) {
      lines.push("", `**PoC:** \`${f.verifyPocPayload}\``);
    }
    if (f.verifyAttackVector) {
      lines.push(`**Attack Vector:** ${f.verifyAttackVector}`);
    }
    lines.push("");
    lines.push("---");
    lines.push("");
  }

  return lines.join("\n");
}

function generateGitHubIssueTemplate(findings: ActionableFinding[], repoName: string): string {
  const actionable = findings.filter((f) => f.verdict !== "fp");
  const critical = actionable.filter((f) => f.severity === "ERROR");
  const exploitable = actionable.filter((f) => f.verifyExploitable === 1);

  const lines = [
    `## Security Scan Results — ${repoName}`,
    "",
    `Kuzushi found **${actionable.length} actionable findings** (${critical.length} critical, ${exploitable.length} exploitable).`,
    "",
    "### Findings",
    "",
  ];

  for (const f of actionable) {
    const badge = f.verifyExploitable === 1 ? " ⚠️ EXPLOITABLE" : "";
    lines.push(`- [ ] **${f.ruleId}** at \`${f.filePath}:${f.startLine}\`${badge}`);
    lines.push(`  ${f.rationale.slice(0, 120)}`);
  }

  lines.push("", "### Remediation Priority", "");
  if (exploitable.length > 0) {
    lines.push(`1. Fix ${exploitable.length} exploitable finding(s) immediately`);
  }
  lines.push(`2. Review ${actionable.length - exploitable.length} remaining finding(s)`);

  return lines.join("\n");
}

function generateJiraCsv(findings: ActionableFinding[]): string {
  const actionable = findings.filter((f) => f.verdict !== "fp");
  const header = "Summary,Priority,Component,Labels,Description";
  const rows = actionable.map((f) => {
    const priority = f.verifyExploitable === 1 ? "Critical"
      : f.severity === "ERROR" ? "High"
      : "Medium";
    const summary = `[Security] ${f.ruleId} in ${f.filePath}:${f.startLine}`;
    const desc = f.rationale.replace(/"/g, '""').slice(0, 500);
    return `"${summary}","${priority}","Security","kuzushi,${f.taskId}","${desc}"`;
  });

  return [header, ...rows].join("\n");
}

function copyToClipboard(text: string): void {
  try {
    const { execSync } = require("node:child_process") as typeof import("node:child_process");
    const platform = process.platform;

    if (platform === "darwin") {
      execSync("pbcopy", { input: text });
    } else if (platform === "linux") {
      // Try xclip first, then xsel, then wl-copy (Wayland)
      try {
        execSync("xclip -selection clipboard", { input: text });
      } catch {
        try {
          execSync("xsel --clipboard --input", { input: text });
        } catch {
          execSync("wl-copy", { input: text });
        }
      }
    } else if (platform === "win32") {
      execSync("clip", { input: text });
    }
  } catch {
    // Clipboard not available — silently fail
  }
}
