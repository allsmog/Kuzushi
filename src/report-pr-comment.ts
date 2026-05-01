/**
 * Markdown PR comment generator — Phase B.5.
 *
 * Turns a `SummaryData` snapshot (optionally with a repo name + run URL)
 * into a short GitHub-flavoured markdown block operators can paste into a
 * PR review or pipe to `gh pr comment -F -`. Intentionally opinionated:
 * one header, one counts table, optional exploit-chain story, optional
 * "new in this PR" lead block, one findings table (top 10), one footer
 * with cost + duration. No embedded ANSI — this output is meant for
 * rendering in a browser.
 *
 * Usage:
 *
 *   const md = buildPrComment(summary, { repoName: "acme-api" });
 *   await fs.writeFile("comment.md", md);
 *
 *   # or pipe to gh:
 *   $ kuzushi comment --pr 123 | gh pr comment 123 -F -
 */

import type { ExploitChain } from "./types.js";
import type { ActionableFinding, SummaryData } from "./ui/state.js";

export interface PrCommentOptions {
  repoName?: string;
  /** Optional link to a run dashboard / artefact (rendered on the header line). */
  runUrl?: string;
  /** How many top findings to include. Default 10. */
  topN?: number;
  /** Override elapsed milliseconds if not derivable from the summary. */
  elapsedMs?: number;
  /**
   * Optional list of files changed in this PR. When supplied, findings whose
   * `filePath` falls inside this set are surfaced in a "New in this PR"
   * lead block above the global table. Operators get this for free from
   * the `/since <ref>` shell verb or `git diff --name-only <base>...HEAD`.
   */
  changedFiles?: ReadonlyArray<string>;
  /** Optional kuzushi version stamp for the footer. */
  kuzushiVersion?: string;
  /** Optional model name stamp for the footer. */
  model?: string;
  /** Optional git sha (short or long) stamp for the footer. */
  gitSha?: string;
  /** Optional run id for the footer. */
  runId?: string;
}

export function buildPrComment(summary: SummaryData, opts: PrCommentOptions = {}): string {
  const repoName = opts.repoName ?? summary.repoName ?? "(unknown repo)";
  const topN = opts.topN ?? 10;
  const findings = summary.actionableFindings ?? [];
  const tpFindings = findings.filter((f) => f.verdict === "tp" && !f.suppressed);
  const sortedTp = [...tpFindings].sort(compareSeverity);

  const changedFiles = normaliseChangedFiles(opts.changedFiles);
  const newInPr = changedFiles
    ? sortedTp.filter((f) => f.filePath && isInChangedFiles(f.filePath, changedFiles))
    : [];

  const verdictLine = renderVerdictCounts(summary, newInPr.length, changedFiles != null);
  const costLine = renderCostLine(summary, opts.elapsedMs);
  const chainsBlock = renderChainsBlock(summary.exploitChains ?? [], findings);
  const newInPrBlock =
    changedFiles != null && newInPr.length > 0
      ? renderFindingsBlock("New in this PR", newInPr, opts.runUrl, newInPr.length)
      : "";
  const findingsTable = renderFindingsBlock(
    `Top findings (${Math.min(topN, sortedTp.length)} of ${sortedTp.length})`,
    sortedTp.slice(0, topN),
    opts.runUrl,
    sortedTp.length,
    topN,
  );

  const headerSuffix = opts.runUrl ? ` · [run](${opts.runUrl})` : "";
  const footer = renderFooter(opts, topN, sortedTp.length);

  const sections: string[] = [
    `### 🔐 Kuzushi scan · \`${repoName}\`${headerSuffix}`,
    "",
    verdictLine,
    "",
    costLine,
  ];
  if (chainsBlock) {
    sections.push("", chainsBlock);
  }
  if (newInPrBlock) {
    sections.push("", newInPrBlock);
  }
  sections.push("", findingsTable, "", footer, "");
  return sections.join("\n");
}

function normaliseChangedFiles(
  files: ReadonlyArray<string> | undefined,
): ReadonlySet<string> | null {
  if (!files) return null;
  const trimmed = files.map((f) => f.trim()).filter((f) => f.length > 0);
  return new Set(trimmed);
}

function isInChangedFiles(filePath: string, changedFiles: ReadonlySet<string>): boolean {
  if (changedFiles.has(filePath)) return true;
  // Some scanners emit absolute paths or repo-prefixed paths; do a suffix check
  // so e.g. `/abs/repo/src/a.ts` matches `src/a.ts` in the diff list.
  for (const f of changedFiles) {
    if (filePath.endsWith(f) || f.endsWith(filePath)) return true;
  }
  return false;
}

function renderVerdictCounts(
  summary: SummaryData,
  newInPrCount: number,
  diffScoped: boolean,
): string {
  const tpFindings = (summary.actionableFindings ?? []).filter(
    (f) => f.verdict === "tp" && !f.suppressed,
  );
  const sevCounts = new Map<string, number>();
  for (const f of tpFindings) {
    const sev = canonicalSeverity(f);
    sevCounts.set(sev, (sevCounts.get(sev) ?? 0) + 1);
  }
  const parts: string[] = [];
  for (const sev of ["critical", "high", "medium", "low"] as const) {
    const count = sevCounts.get(sev) ?? 0;
    if (count > 0) parts.push(`${severityIcon(sev)} **${count} ${sev}**`);
  }
  if (parts.length === 0) {
    // Fall back to verdict-count rendering when actionableFindings is empty
    // but verdictCounts is populated (older summaries built by `buildSummaryData`
    // before the actionableFindings projection landed).
    const cells: Array<[string, number]> = [];
    for (const [k, v] of Object.entries(summary.verdictCounts ?? {})) {
      if (v > 0) cells.push([k, v]);
    }
    if (cells.length === 0) return "**No findings triaged.**";
    const text = cells.map(([k, v]) => `**${v}** ${k}`).join(" · ");
    const exploitablePart =
      summary.exploitable > 0 ? ` · 🔓 **${summary.exploitable} exploitable**` : "";
    const newInPrPart = diffScoped ? ` · 🆕 **${newInPrCount} new in this PR**` : "";
    return `${text}${exploitablePart}${newInPrPart}`;
  }
  if (summary.exploitable > 0) {
    parts.push(`🔓 **${summary.exploitable} exploitable**`);
  }
  if (diffScoped) {
    parts.push(`🆕 **${newInPrCount} new in this PR**`);
  }
  return parts.join(" · ");
}

function renderCostLine(summary: SummaryData, overrideElapsedMs?: number): string {
  const triage = summary.triageCostUsd ?? 0;
  const verify = summary.verificationCostUsd ?? 0;
  const poc = summary.pocHarnessCostUsd ?? 0;
  const variant = summary.variantAnalysisCostUsd ?? 0;
  const total = triage + verify + poc + variant;
  const phaseParts: string[] = [];
  if (triage > 0) phaseParts.push(`triage $${triage.toFixed(2)}`);
  if (verify > 0) phaseParts.push(`verify $${verify.toFixed(2)}`);
  if (poc > 0) phaseParts.push(`poc $${poc.toFixed(2)}`);
  if (variant > 0) phaseParts.push(`variant $${variant.toFixed(2)}`);
  const phaseBlock = phaseParts.length > 0 ? `\`${phaseParts.join(" · ")}\` — ` : "";
  let line = `${phaseBlock}total **$${total.toFixed(2)}**`;
  if (overrideElapsedMs != null) line += ` in ${formatDuration(overrideElapsedMs)}`;
  if (summary.pocGenerated > 0) line += ` · 🧪 ${summary.pocGenerated} PoCs`;
  if (summary.variantFindings > 0) line += ` · 🧬 ${summary.variantFindings} variants`;
  // Preserve historical spend marker so legacy parsers still match.
  return `💸 ${line}`;
}

function renderChainsBlock(
  chains: ReadonlyArray<ExploitChain>,
  findings: ReadonlyArray<ActionableFinding>,
): string {
  if (!chains || chains.length === 0) return "";
  const findingByFp = new Map(findings.map((f) => [f.fingerprint, f] as const));
  const sorted = [...chains].sort(
    (a, b) => chainSeverityRank(a.overallSeverity) - chainSeverityRank(b.overallSeverity),
  );
  const blocks: string[] = [
    `#### 🔗 Exploit chain${sorted.length === 1 ? "" : "s"} (${sorted.length})`,
  ];
  sorted.forEach((chain, idx) => {
    const alias = `C-${String(idx + 1).padStart(2, "0")}`;
    const sev = chain.overallSeverity;
    const stepCount = chain.steps.length;
    const heading = `**${alias} · ${sev} · ${stepCount} step${stepCount === 1 ? "" : "s"}** — ${escapeMd(
      chain.narrative ?? chain.impactDescription ?? chain.name,
    )}`;
    blocks.push("");
    blocks.push(heading);
    blocks.push("");
    chain.steps.forEach((step, stepIdx) => {
      const finding = findingByFp.get(step.findingFingerprint);
      const filePath = step.filePath ?? finding?.filePath ?? "?";
      const startLine = step.startLine ?? finding?.startLine ?? "?";
      const title = finding?.title ?? finding?.ruleId ?? step.description ?? "";
      blocks.push(
        `${stepIdx + 1}. **${escapeMd(step.role || "step")}** \`${filePath}:${startLine}\` — ${escapeMd(title)}`,
      );
    });
    if (chain.impactDescription || chain.preconditions.length > 0) {
      blocks.push("");
      const impact = chain.impactDescription
        ? `**Impact:** ${escapeMd(chain.impactDescription)}`
        : "";
      const pre =
        chain.preconditions.length > 0
          ? `**Preconditions:** ${chain.preconditions.map(escapeMd).join("; ")}`
          : "**Preconditions:** none";
      blocks.push(`> ${[impact, pre].filter(Boolean).join(" ")}`);
    }
  });
  return blocks.join("\n");
}

function renderFindingsBlock(
  heading: string,
  rows: ReadonlyArray<ActionableFinding>,
  runUrl: string | undefined,
  totalCount: number,
  topN?: number,
): string {
  if (rows.length === 0) {
    return `#### ${heading}\n\n_No true-positive findings._`;
  }
  const out: string[] = [`#### ${heading}`, ""];
  out.push("| ID | Severity | CWE | Title | Location |");
  out.push("|----|----------|-----|-------|----------|");
  rows.forEach((f, i) => {
    const alias = `F-${String(i + 1).padStart(4, "0")}`;
    const idCell = runUrl ? `[${alias}](${runUrl}#${alias})` : alias;
    const sev = severityBadge(f);
    const cwe = (f.cwe ?? []).slice(0, 2).join(", ") || "—";
    const title = escapeMd(f.title ?? f.ruleId ?? "(untitled)");
    const loc = `\`${f.filePath ?? "?"}:${f.startLine ?? "?"}\``;
    out.push(`| ${idCell} | ${sev} | ${escapeMd(cwe)} | ${title} | ${loc} |`);
    if (f.remediation) {
      out.push("");
      out.push(`> ${escapeMd(f.remediation)}`);
      out.push("");
    }
  });
  if (topN != null && totalCount > rows.length) {
    out.push("");
    out.push(
      `_… and **${totalCount - rows.length}** more findings (truncated; raise \`topN\` to see them)._`,
    );
  }
  return out.join("\n");
}

function renderFooter(opts: PrCommentOptions, topN: number, total: number): string {
  const stamps: string[] = [];
  if (opts.kuzushiVersion) stamps.push(`Kuzushi ${opts.kuzushiVersion}`);
  else stamps.push("Kuzushi");
  if (opts.runId) stamps.push(`run \`${opts.runId.slice(0, 8)}\``);
  if (opts.model) stamps.push(`model \`${opts.model}\``);
  if (opts.gitSha) stamps.push(`git \`${opts.gitSha.slice(0, 7)}\``);
  const stamp = stamps.join(" · ");
  const truncated = Math.max(0, total - topN);
  const truncatedNote =
    total === 0
      ? `Showing top ${topN}.`
      : `Showing top ${Math.min(topN, total)}; ${truncated} truncated.`;
  return `<sub>Generated by [${stamp}](https://github.com/allsmog/Kuzushi). ${truncatedNote}</sub>`;
}

function severityBadge(f: ActionableFinding): string {
  const sev = canonicalSeverity(f);
  switch (sev) {
    case "critical":
      return "🟥 CRIT";
    case "high":
      return "🟧 HIGH";
    case "medium":
      return "🟨 MED";
    default:
      return "⬜ LOW";
  }
}

function severityIcon(sev: "critical" | "high" | "medium" | "low"): string {
  switch (sev) {
    case "critical":
      return "🟥";
    case "high":
      return "🟧";
    case "medium":
      return "🟨";
    default:
      return "⬜";
  }
}

function canonicalSeverity(f: ActionableFinding): "critical" | "high" | "medium" | "low" {
  const sev = (f.displaySeverity ?? f.severity ?? "").toLowerCase();
  if (sev.includes("crit")) return "critical";
  if (sev.includes("high")) return "high";
  if (sev.includes("med")) return "medium";
  return "low";
}

function chainSeverityRank(sev: ExploitChain["overallSeverity"]): number {
  switch (sev) {
    case "CRITICAL":
      return 0;
    case "HIGH":
      return 1;
    case "MEDIUM":
      return 2;
    default:
      return 3;
  }
}

function compareSeverity(a: ActionableFinding, b: ActionableFinding): number {
  const order = ["critical", "high", "medium", "low"];
  const da = order.indexOf(canonicalSeverity(a));
  const db = order.indexOf(canonicalSeverity(b));
  if (da === db) return (a.fingerprint ?? "").localeCompare(b.fingerprint ?? "");
  return (da < 0 ? 99 : da) - (db < 0 ? 99 : db);
}

function formatDuration(ms: number): string {
  const secs = Math.max(0, Math.floor(ms / 1000));
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return s === 0 ? `${m}m` : `${m}m ${s}s`;
}

function escapeMd(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/\n/g, " ");
}
