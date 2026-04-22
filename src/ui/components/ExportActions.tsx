/**
 * Finding export action menu — shown after pipeline or review completes.
 *
 * Offers one-keypress export options:
 *   [c] Copy findings to clipboard (markdown)
 *   [g] Generate GitHub issue template
 *   [j] Export as Jira CSV
 *   [enter] done
 */

import { execSync } from "node:child_process";
import { Box, Text, useInput } from "ink";
import type React from "react";
import { useState } from "react";
import { boxFooter, boxHeader, terminalCardWidth } from "../format.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { icons } from "../icons.js";
import type { ActionableFinding } from "../state.js";
import { SPACING, tokens } from "../tokens.js";

interface ExportActionsProps {
  findings: ActionableFinding[];
  repoName: string;
  onDone: () => void;
}

export function ExportActions({
  findings,
  repoName,
  onDone,
}: ExportActionsProps): React.ReactElement {
  const [status, setStatus] = useState<string | null>(null);
  const width = terminalCardWidth();

  const actionableCount = findings.filter((f) => f.verdict !== "fp").length;

  useRegisterKeybindings([
    { keys: "c", label: "Copy markdown" },
    { keys: "g", label: "GitHub template" },
    { keys: "j", label: "Jira CSV" },
    { keys: "Enter", label: "Done", secondary: true },
  ]);

  useInput((input, key) => {
    if (key.return || key.escape) {
      onDone();
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
      <Text>{boxHeader("Export", width)}</Text>
      <Text>{""}</Text>
      <Box paddingLeft={SPACING.md}>
        <Text>{tokens.muted(`${actionableCount} actionable findings available`)}</Text>
      </Box>
      <Text>{""}</Text>
      <Box flexDirection="column" paddingLeft={SPACING.md}>
        <Text>
          {tokens.dangerStrong("[c]")} Copy to clipboard {tokens.muted("(markdown)")}
        </Text>
        <Text>{tokens.strong("[g]")} GitHub issue template</Text>
        <Text>{tokens.info("[j]")} Jira CSV export</Text>
      </Box>

      {status && (
        <Box paddingLeft={SPACING.md} marginTop={SPACING.sm}>
          <Text>{tokens.success(status)}</Text>
        </Box>
      )}

      <Text>{""}</Text>
      <Text>{boxFooter(width)}</Text>
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
    const severity = f.severity === "ERROR" ? "\uD83D\uDD34" : "\uD83D\uDFE1";
    const verdict =
      f.verdict === "tp"
        ? "TRUE POSITIVE"
        : f.verdict === "needs_review"
          ? "NEEDS REVIEW"
          : f.verdict.toUpperCase();
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
    const flag = f.verifyExploitable === 1 ? " \u26A0 EXPLOITABLE" : "";
    lines.push(`- [ ] **${f.ruleId}** at \`${f.filePath}:${f.startLine}\`${flag}`);
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
    const priority =
      f.verifyExploitable === 1 ? "Critical" : f.severity === "ERROR" ? "High" : "Medium";
    const summary = `[Security] ${f.ruleId} in ${f.filePath}:${f.startLine}`;
    const desc = f.rationale.replace(/"/g, '""').slice(0, 500);
    return `"${summary}","${priority}","Security","kuzushi,${f.taskId}","${desc}"`;
  });

  return [header, ...rows].join("\n");
}

function copyToClipboard(text: string): void {
  try {
    const platform = process.platform;
    if (platform === "darwin") {
      execSync("pbcopy", { input: text });
    } else if (platform === "linux") {
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
