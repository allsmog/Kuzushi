/**
 * Interactive setup wizard for first-time users.
 *
 * Walks through preset selection, then optionally model/save-location.
 * Saves config to .kuzushi/config.json or ~/.kuzushi/config.json.
 *
 * Uses the shared <SelectList> primitive with a custom renderItem that
 * shows a detail block beneath the currently-highlighted option.
 */

import { Box, Text, useInput } from "ink";
import type React from "react";
import { useState } from "react";
import { boxFooter, boxHeader } from "../format.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { useTerminalCardWidth } from "../hooks.js";
import { icons } from "../icons.js";
import {
  SelectList,
  type SelectListItem,
  type SelectListRenderContext,
} from "../primitives/SelectList.js";
import { SPACING, tokens } from "../tokens.js";

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

interface RichOption {
  id: string;
  icon: string;
  name: string;
  description: string;
  detail: string;
  summary: string;
}

const PRESETS: RichOption[] = [
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
    icon: tokens.danger("\u25C9"),
    name: "Reference",
    description: "augment current config",
    detail:
      "Keeps your configured tasks and adds verify, PoC harnesses, code graph, and dynamic selection.",
    summary: "Highest operator cost. Does not auto-enable patching by itself.",
  },
];

type WizardStep = "preset" | "model" | "save";

const STEP_ORDER: WizardStep[] = ["preset", "model", "save"];

const MODELS: RichOption[] = [
  {
    id: "anthropic:claude-sonnet-4-6",
    icon: icons.complete,
    name: "Claude Sonnet",
    description: "Anthropic — balanced (recommended)",
    detail: "Best price/accuracy ratio for most scans.",
    summary: "Picks triage, verify, and PoC generation without breaking the bank.",
  },
  {
    id: "anthropic:claude-opus-4-6",
    icon: icons.active,
    name: "Claude Opus",
    description: "Anthropic — most accurate",
    detail: "Highest recall + reasoning depth. Significantly higher cost.",
    summary: "Use for deep investigative runs or when accuracy beats cost.",
  },
  {
    id: "anthropic:claude-haiku-4-5",
    icon: icons.lightning,
    name: "Claude Haiku",
    description: "Anthropic — fastest + cheapest",
    detail: "Speed-first. Lower accuracy; skip verify-heavy presets.",
    summary: "Ideal for huge repos where per-finding cost dominates.",
  },
  {
    id: "openai:gpt-5-mini",
    icon: icons.complete,
    name: "GPT-5 mini",
    description: "OpenAI — balanced",
    detail: "GPT-5 with tool use via Responses API. Supports reasoning effort control.",
    summary: "Swap in if you prefer OpenAI or already have an OPENAI_API_KEY.",
  },
  {
    id: "openai:gpt-5",
    icon: icons.active,
    name: "GPT-5",
    description: "OpenAI — most capable",
    detail: "Full GPT-5. Best for complex reasoning.",
    summary: "Anthropic equivalent: Opus. Higher cost per finding.",
  },
  {
    id: "google:gemini-2.5-pro",
    icon: icons.active,
    name: "Gemini 2.5 Pro",
    description: "Google — strong multi-step",
    detail: "Large context window, good tool-use. Requires GOOGLE_API_KEY.",
    summary: "Great for monorepo-scale scans with lots of file reads per finding.",
  },
  {
    id: "google:gemini-2.5-flash",
    icon: icons.lightning,
    name: "Gemini 2.5 Flash",
    description: "Google — fast + cheap",
    detail: "Speed/cost-optimized Gemini. Accuracy slightly below Pro.",
    summary: "Good Ollama alternative when you want cloud speed at low cost.",
  },
  {
    id: "groq:llama-3.3-70b-versatile",
    icon: icons.lightning,
    name: "Llama 3.3 on Groq",
    description: "Groq — ultra-fast OSS",
    detail: "Fastest inference available for Llama. Requires GROQ_API_KEY.",
    summary: "Use when latency matters more than peak accuracy.",
  },
  {
    id: "openrouter:anthropic/claude-sonnet-4-6",
    icon: icons.gear,
    name: "OpenRouter",
    description: "Any model, unified billing",
    detail: "Proxies 100+ models. Pick any OpenRouter model ID via /config later.",
    summary: "Best when you want to experiment across providers from one key.",
  },
];

const SAVE_OPTIONS: RichOption[] = [
  {
    id: "project",
    icon: icons.complete,
    name: "Save to project",
    description: ".kuzushi/config.json",
    detail: "Commit-ready path. Shares settings with everyone on the team.",
    summary: "Recommended when the settings apply broadly to this repo.",
  },
  {
    id: "global",
    icon: icons.complete,
    name: "Save globally",
    description: "~/.kuzushi/config.json",
    detail: "Per-user path. Keeps settings private to your machine.",
    summary: "Use when preferences reflect your workflow, not the repo.",
  },
  {
    id: "none",
    icon: icons.info,
    name: "Don't save",
    description: "Use for this run only",
    detail: "No file written. Settings discarded after this scan.",
    summary: "Pick when you're experimenting and don't want artifacts.",
  },
];

function toSelectItems(options: RichOption[]): SelectListItem<string>[] {
  return options.map((opt) => ({
    id: opt.id,
    label: opt.name,
    detail: opt.description,
  }));
}

function richRenderer(options: RichOption[]) {
  return (ctx: SelectListRenderContext<string>): React.ReactElement => {
    const opt = options.find((o) => o.id === ctx.item.id);
    if (!opt) return <Text>{ctx.item.label}</Text>;
    const name = ctx.isCursor ? tokens.strong(opt.name) : tokens.muted(opt.name);
    return (
      <Box flexDirection="column" paddingLeft={SPACING.md}>
        <Text>
          {ctx.cursorPrefix} {opt.icon} {name} {tokens.muted(opt.description)}
        </Text>
        {ctx.isCursor && (
          <>
            <Box paddingLeft={SPACING.xxxl}>
              <Text>{tokens.muted(opt.detail)}</Text>
            </Box>
            <Box paddingLeft={SPACING.xxxl}>
              <Text>{tokens.strong(opt.summary)}</Text>
            </Box>
          </>
        )}
      </Box>
    );
  };
}

export function SetupWizard({
  repoName,
  onComplete,
  onCancel,
}: SetupWizardProps): React.ReactElement {
  const [step, setStep] = useState<WizardStep>("preset");
  const [result, setResult] = useState<Partial<WizardResult>>({});
  const width = useTerminalCardWidth();

  useRegisterKeybindings([
    { keys: "\u2191/\u2193", label: "Navigate" },
    { keys: "Enter", label: "Select" },
    { keys: "q", label: "Quit", secondary: true },
  ]);

  const currentOptions = step === "preset" ? PRESETS : step === "model" ? MODELS : SAVE_OPTIONS;

  const stepTitle =
    step === "preset"
      ? `Setup \u2014 ${repoName}`
      : step === "model"
        ? "Choose a model"
        : "Save configuration?";

  const stepHint =
    step === "preset"
      ? "Choose a scan preset:"
      : step === "model"
        ? "Which AI model for triage?"
        : "Where should we save these settings?";

  const currentStep = STEP_ORDER.indexOf(step) + 1;

  const handleSelect = (id: string) => {
    if (step === "preset") {
      setResult((r) => ({ ...r, preset: id }));
      setStep("model");
    } else if (step === "model") {
      setResult((r) => ({ ...r, model: id }));
      setStep("save");
    } else {
      const final: WizardResult = {
        preset: result.preset!,
        model: result.model,
        saveLocation: id as "project" | "global" | "none",
      };
      onComplete(final);
    }
  };

  // Esc/q handling — delegated to a one-off listener rather than tangling the
  // SelectList's useInput. isActive gating ensures no keystroke leak.
  useEscapeCancel(onCancel);

  return (
    <Box flexDirection="column">
      <Text>{""}</Text>
      <Text>{boxHeader(stepTitle, width)}</Text>
      <Text>{""}</Text>
      <Box paddingLeft={SPACING.md}>
        <Text>{tokens.muted(stepHint)}</Text>
      </Box>
      <Box paddingLeft={SPACING.md}>
        <Text>{tokens.hint(`Step ${currentStep} of ${STEP_ORDER.length}`)}</Text>
      </Box>
      <Text>{""}</Text>

      <SelectList
        items={toSelectItems(currentOptions)}
        onSelect={handleSelect}
        renderItem={richRenderer(currentOptions)}
      />

      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}

/** Minimal Escape / "q" cancel handler. */
function useEscapeCancel(onCancel: () => void): void {
  useInput((input, key) => {
    if (input === "q" || key.escape) onCancel();
  });
}
