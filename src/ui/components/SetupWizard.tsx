/**
 * Interactive setup wizard for first-time users.
 *
 * Walks through preset selection, then optionally model/severity/verification.
 * Saves config to .kuzushi/config.json or ~/.kuzushi/config.json.
 *
 *   ┌─ Welcome to Kuzushi ──────────────────────────────────┐
 *   │                                                        │
 *   │  Choose a scan preset:                                 │
 *   │                                                        │
 *   │  > ⚡ Quick       semgrep only (~30s, ~$0.50)          │
 *   │    ◆ Standard     semgrep + taint analysis (~3min)     │
 *   │    ◆ Deep         all scanners + threat model (~10min) │
 *   │    ⚙ Custom       pick individual options              │
 *   │                                                        │
 *   │  [↑↓] navigate  [enter] select                        │
 *   └────────────────────────────────────────────────────────┘
 */

import chalk from "chalk";
import { Box, Text, useInput } from "ink";
import type React from "react";
import { useState } from "react";
import { boxFooter, boxHeader, terminalCardWidth } from "../format.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { icons } from "../icons.js";

export interface WizardResult {
  preset: string;
  model?: string;
  verify?: boolean;
  pocHarness?: boolean;
  severity?: string[];
  saveLocation?: "project" | "global" | "none";
}

interface SetupWizardProps {
  repoName: string;
  onComplete: (result: WizardResult) => void;
  onCancel: () => void;
}

interface PresetOption {
  id: string;
  icon: string;
  name: string;
  description: string;
  detail: string;
  summary: string;
}

const PRESETS: PresetOption[] = [
  {
    id: "fast",
    icon: icons.lightning,
    name: "Fast",
    description: "semgrep only",
    detail: "One scanner, no context-gathering, lowest cost.",
    summary: "Best for a quick pass or CI smoke scan.",
  },
  {
    id: "safe",
    icon: icons.complete,
    name: "Safe",
    description: "context + secrets detection",
    detail: "Context gatherer + enricher + secrets/config tasks, triage capped to 20 findings.",
    summary: "Recommended first interactive scan. No verify or PoC stages.",
  },
  {
    id: "standard",
    icon: icons.active,
    name: "Standard",
    description: "context + taint pipeline",
    detail: "Adds taint CWE selection and IRIS taint analysis to the safe baseline.",
    summary: "Good default for application code with meaningful data-flow coverage.",
  },
  {
    id: "deep",
    icon: icons.gear,
    name: "Deep",
    description: "threat model + hunt + verify",
    detail: "Adds threat modeling, hunt/system tasks, verification, and variant analysis.",
    summary: "Use when you want a full interactive audit, not just a baseline scan.",
  },
  {
    id: "reference",
    icon: chalk.redBright("◉"),
    name: "Reference",
    description: "augment current config",
    detail:
      "Keeps your configured tasks and adds verify, PoC harnesses, code graph, and dynamic selection.",
    summary: "Highest operator cost. Does not auto-enable patching by itself.",
  },
];

type WizardStep = "preset" | "model" | "save" | "done";

const MODELS = [
  {
    id: "anthropic:claude-sonnet-4-6",
    name: "Claude Sonnet",
    detail: "Fast, cost-effective (default)",
  },
  { id: "anthropic:claude-opus-4-6", name: "Claude Opus", detail: "Most accurate, slower" },
  { id: "anthropic:claude-haiku-4-5", name: "Claude Haiku", detail: "Fastest, cheapest" },
];

const SAVE_OPTIONS = [
  {
    id: "project" as const,
    name: "Save to project",
    detail: ".kuzushi/config.json (shared with team)",
  },
  { id: "global" as const, name: "Save globally", detail: "~/.kuzushi/config.json (personal)" },
  { id: "none" as const, name: "Don't save", detail: "Use these settings for this run only" },
];

export function SetupWizard({
  repoName,
  onComplete,
  onCancel,
}: SetupWizardProps): React.ReactElement {
  const [step, setStep] = useState<WizardStep>("preset");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [result, setResult] = useState<Partial<WizardResult>>({});
  const width = terminalCardWidth();

  useRegisterKeybindings([
    { keys: "\u2191/\u2193", label: "Navigate" },
    { keys: "Enter", label: "Select" },
    { keys: "q", label: "Quit", secondary: true },
  ]);

  const currentOptions =
    step === "preset" ? PRESETS : step === "model" ? MODELS : step === "save" ? SAVE_OPTIONS : [];

  useInput((input, key) => {
    if (input === "q" || key.escape) {
      onCancel();
      return;
    }

    if (key.upArrow) {
      setSelectedIndex((i) => Math.max(0, i - 1));
      return;
    }
    if (key.downArrow) {
      setSelectedIndex((i) => Math.min(currentOptions.length - 1, i + 1));
      return;
    }

    if (key.return) {
      if (step === "preset") {
        const preset = PRESETS[selectedIndex]!;
        setResult((r) => ({ ...r, preset: preset.id }));
        setStep("model");
        setSelectedIndex(0);
      } else if (step === "model") {
        const model = MODELS[selectedIndex]!;
        setResult((r) => ({ ...r, model: model.id }));
        setStep("save");
        setSelectedIndex(0);
      } else if (step === "save") {
        const save = SAVE_OPTIONS[selectedIndex]!;
        const final: WizardResult = {
          preset: result.preset!,
          model: result.model,
          saveLocation: save.id,
        };
        onComplete(final);
      }
    }
  });

  const stepTitle =
    step === "preset"
      ? `Setup — ${repoName}`
      : step === "model"
        ? "Choose a model"
        : "Save configuration?";

  const stepHint =
    step === "preset"
      ? "Choose a scan preset:"
      : step === "model"
        ? "Which AI model for triage?"
        : "Where should we save these settings?";

  return (
    <Box flexDirection="column">
      <Text>{""}</Text>
      <Text>{boxHeader(stepTitle, width)}</Text>
      <Text>{""}</Text>
      <Text>
        {"  "}
        {chalk.dim(stepHint)}
      </Text>
      <Text>{""}</Text>

      {currentOptions.map((option, i) => {
        const isSelected = i === selectedIndex;
        const prefix = isSelected ? chalk.redBright(icons.arrow) : " ";
        const name = isSelected ? chalk.white.bold(option.name) : chalk.dim(option.name);
        const icon = "icon" in option ? (option as PresetOption).icon : icons.complete;
        const desc =
          "description" in option
            ? chalk.dim((option as PresetOption).description)
            : chalk.dim(option.detail);
        const summary = "summary" in option ? (option as PresetOption).summary : option.detail;

        return (
          <Box key={i} flexDirection="column">
            <Text>
              {"  "}
              {prefix} {icon} {name} {desc}
            </Text>
            {isSelected && (
              <>
                <Text>
                  {"      "}
                  {chalk.dim(option.detail)}
                </Text>
                <Text>
                  {"      "}
                  {chalk.white(summary)}
                </Text>
              </>
            )}
          </Box>
        );
      })}

      <Text>{""}</Text>
      <Text>
        {"  "}
        {chalk.dim("[↑↓] navigate  [enter] select  [q] quit")}
      </Text>
      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}
