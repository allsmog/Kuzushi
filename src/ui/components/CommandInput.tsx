/**
 * Interactive command input for live scan control.
 *
 * Sits at the bottom of the Ink app, accepting slash commands:
 *   /skip <fingerprint>   — skip a finding during triage
 *   /skip-rule <ruleId>   — suppress all findings matching a rule
 *   /focus <path>         — prioritize findings in a path
 *   /pause                — pause triage after current finding
 *   /resume               — resume triage
 *   /status               — show current scan stats
 *   /cost                 — show cost breakdown
 *   /export               — open export menu
 *   /help or ?            — show available commands
 */

import chalk from "chalk";
import { Box, Text, useInput } from "ink";
import type React from "react";
import { useState } from "react";
import { icons } from "../icons.js";

export interface ReplCommand {
  name: string;
  args: string[];
  raw: string;
}

export interface CommandResult {
  message: string;
  type: "success" | "error" | "info";
}

interface CommandInputProps {
  /** Whether the input is active (accepts typing). */
  active: boolean;
  /** Callback when a command is submitted. */
  onCommand: (cmd: ReplCommand) => CommandResult | undefined;
}

const COMMANDS: Array<{ name: string; args: string; desc: string }> = [
  { name: "/skip", args: "<fingerprint>", desc: "Skip a finding" },
  { name: "/skip-rule", args: "<ruleId>", desc: "Suppress findings by rule" },
  { name: "/focus", args: "<path>", desc: "Prioritize findings in path" },
  { name: "/pause", args: "", desc: "Pause after current finding" },
  { name: "/resume", args: "", desc: "Resume triage" },
  { name: "/status", args: "", desc: "Show current stats" },
  { name: "/cost", args: "", desc: "Show cost breakdown" },
  { name: "/help", args: "", desc: "Show this help" },
];

export function CommandInput({ active, onCommand }: CommandInputProps): React.ReactElement | null {
  const [input, setInput] = useState("");
  const [lastResult, setLastResult] = useState<CommandResult | null>(null);
  const [showHelp, setShowHelp] = useState(false);
  const [expanded, setExpanded] = useState(false);

  // Guard: stdin must support raw mode for useInput to work
  const canUseInput = active && process.stdin.isTTY === true;

  useInput(
    (char, key) => {
      if (!expanded && char === "/") {
        setExpanded(true);
        setInput("/");
        return;
      }

      if (!expanded && char === "?") {
        setExpanded(true);
        setShowHelp(true);
        setLastResult({ message: "", type: "info" });
        return;
      }

      if (!expanded) {
        return;
      }

      if (key.return && input.length > 0) {
        const cmd = parseCommand(input);
        if (cmd) {
          if (cmd.name === "help") {
            setShowHelp((v) => !v);
            setLastResult({ message: "", type: "info" });
          } else {
            const result = onCommand(cmd);
            setLastResult(result ?? { message: `${cmd.name}: ok`, type: "success" });
            setShowHelp(false);
          }
        } else {
          setLastResult({ message: `Unknown command: ${input}`, type: "error" });
        }
        setInput("");
        setExpanded(false);
        return;
      }

      if (key.backspace || key.delete) {
        setInput((v) => v.slice(0, -1));
        return;
      }

      if (key.escape) {
        setInput("");
        setLastResult(null);
        setShowHelp(false);
        setExpanded(false);
        return;
      }

      // Only accept printable characters
      if (char && !key.ctrl && !key.meta && char.length === 1) {
        setInput((v) => v + char);
      }
    },
    { isActive: canUseInput },
  );

  if (!active || !process.stdin.isTTY) return null;

  return (
    <Box flexDirection="column" marginTop={1}>
      {/* Help overlay */}
      {showHelp && (
        <Box flexDirection="column" marginBottom={1}>
          <Text>
            {"  "}
            {chalk.dim("Available commands:")}
          </Text>
          {COMMANDS.map((cmd) => (
            <Text key={cmd.name}>
              {"    "}
              {chalk.redBright(cmd.name)} {chalk.dim(cmd.args)}
              {"  "}
              {chalk.dim(cmd.desc)}
            </Text>
          ))}
          <Text>{""}</Text>
        </Box>
      )}

      {/* Last command result */}
      {lastResult?.message && (
        <Text>
          {"  "}
          {lastResult.type === "success"
            ? chalk.green(icons.success)
            : lastResult.type === "error"
              ? chalk.red(icons.error)
              : chalk.dim(icons.dot)}{" "}
          {lastResult.type === "error"
            ? chalk.red(lastResult.message)
            : chalk.dim(lastResult.message)}
        </Text>
      )}

      {/* Input line */}
      {expanded && (
        <Text>
          {"  "}
          {chalk.dim(icons.arrow)} {input}
          {chalk.redBright("█")}
          {input.length === 0 && chalk.dim(" type / for commands, ? for help")}
        </Text>
      )}
    </Box>
  );
}

function parseCommand(raw: string): ReplCommand | null {
  const trimmed = raw.trim();

  if (trimmed === "?") {
    return { name: "help", args: [], raw: trimmed };
  }

  if (!trimmed.startsWith("/")) {
    return null;
  }

  const parts = trimmed.slice(1).split(/\s+/);
  const name = parts[0]!;
  const args = parts.slice(1);

  const validNames = COMMANDS.map((c) => c.name.slice(1));
  if (!validNames.includes(name)) {
    return null;
  }

  return { name, args, raw: trimmed };
}
