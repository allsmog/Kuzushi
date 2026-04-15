/**
 * Attack chain flow diagram — ASCII art visualization of exploit chains.
 *
 * Renders each chain as boxed steps connected by arrows:
 *
 *   ╭─ Stored XSS via Template Injection ──── CRITICAL ────╮
 *   │                                                       │
 *   │  ┌──────────────┐    ┌─────────────┐    ┌──────────┐  │
 *   │  │ POST /api/   │───→│ template    │───→│ browser  │  │
 *   │  │ comments     │    │ engine      │    │ render   │  │
 *   │  │   (entry)    │    │ (propagate) │    │  (sink)  │  │
 *   │  └──────────────┘    └─────────────┘    └──────────┘  │
 *   │                                                       │
 *   │  ⚠ Full account takeover via cookie theft             │
 *   │  Requires: User can submit comments                   │
 *   ╰───────────────────────────────────────────────────────╯
 */
import React from "react";
import { Box, Text } from "ink";
import chalk from "chalk";
import { icons } from "../icons.js";
import { badge } from "../format.js";
import type { ExploitChain } from "../../types.js";

interface AttackChainDiagramProps {
  chain: ExploitChain;
}

// Box widths for step rendering
const STEP_INNER_WIDTH = 18;
const ARROW = " ───→ ";

export function AttackChainDiagram({ chain }: AttackChainDiagramProps): React.ReactElement {
  const sevColor = chain.overallSeverity === "CRITICAL" ? chalk.red.bold
    : chain.overallSeverity === "HIGH" ? chalk.red
    : chalk.yellow;

  const borderColor = chain.overallSeverity === "CRITICAL" ? chalk.red
    : chain.overallSeverity === "HIGH" ? chalk.red
    : chalk.yellow;

  // Build step boxes
  const steps = chain.steps.map((step) => buildStepBox(step.description, step.role));

  // Calculate total width
  const boxWidth = STEP_INNER_WIDTH + 2; // +2 for borders
  const totalInner = (boxWidth * steps.length) + (ARROW.length * (steps.length - 1)) + 4;
  const outerWidth = Math.max(totalInner, chain.name.length + chain.overallSeverity.length + 12);

  // Render title bar
  const titleText = ` ${chain.name} `;
  const sevText = ` ${chain.overallSeverity} `;
  const fillLen = Math.max(0, outerWidth - titleText.length - sevText.length - 2);
  const titleLine = `${borderColor("╭─")}${borderColor(titleText)}${borderColor("─".repeat(fillLen))}${sevColor(sevText)}${borderColor("─╮")}`;

  // Build the three lines of each step box (top, content, bottom)
  const stepTop = steps.map((s) => s.top).join(chalk.dim(ARROW.replace(/[─→]/g, " ")));
  const stepMid1 = steps.map((s) => s.line1).join(chalk.dim(ARROW));
  const stepMid2 = steps.map((s) => s.line2).join(chalk.dim(ARROW.replace(/[─→]/g, " ")));
  const stepRole = steps.map((s) => s.role).join(chalk.dim(ARROW.replace(/[─→]/g, " ")));
  const stepBot = steps.map((s) => s.bottom).join(chalk.dim(ARROW.replace(/[─→]/g, " ")));

  return (
    <Box flexDirection="column">
      <Text>{"  "}{titleLine}</Text>
      <Text>{"  "}{borderColor("│")}</Text>
      <Text>{"  "}{borderColor("│")}  {stepTop}</Text>
      <Text>{"  "}{borderColor("│")}  {stepMid1}</Text>
      <Text>{"  "}{borderColor("│")}  {stepMid2}</Text>
      <Text>{"  "}{borderColor("│")}  {stepRole}</Text>
      <Text>{"  "}{borderColor("│")}  {stepBot}</Text>
      <Text>{"  "}{borderColor("│")}</Text>
      <Text>{"  "}{borderColor("│")}  {icons.warning} {chain.impactDescription}</Text>
      {chain.preconditions.length > 0 && (
        <Text>{"  "}{borderColor("│")}  {chalk.dim(`Requires: ${chain.preconditions.join(", ")}`)}</Text>
      )}
      <Text>{"  "}{borderColor(`╰${"─".repeat(Math.max(outerWidth, 40))}╯`)}</Text>
    </Box>
  );
}

interface StepBox {
  top: string;
  line1: string;
  line2: string;
  role: string;
  bottom: string;
}

function buildStepBox(description: string, role: string): StepBox {
  const w = STEP_INNER_WIDTH;

  // Split description into two lines if needed
  const words = description.split(" ");
  let line1 = "";
  let line2 = "";

  for (const word of words) {
    if (line1.length + word.length + 1 <= w) {
      line1 += (line1 ? " " : "") + word;
    } else {
      line2 += (line2 ? " " : "") + word;
    }
  }

  // Truncate if still too long
  if (line1.length > w) line1 = line1.slice(0, w - 1) + "…";
  if (line2.length > w) line2 = line2.slice(0, w - 1) + "…";

  const roleText = `(${role})`;
  const padRole = roleText.length > w ? roleText.slice(0, w) : roleText;

  return {
    top: chalk.dim(`┌${"─".repeat(w)}┐`),
    line1: chalk.dim("│") + chalk.white(line1.padEnd(w)) + chalk.dim("│"),
    line2: chalk.dim("│") + chalk.white(line2.padEnd(w)) + chalk.dim("│"),
    role: chalk.dim("│") + chalk.dim(padRole.padEnd(w)) + chalk.dim("│"),
    bottom: chalk.dim(`└${"─".repeat(w)}┘`),
  };
}
