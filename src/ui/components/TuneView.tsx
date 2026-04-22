/**
 * TuneView — the six plain controls for a module (D6, Ink UI v2 screen 06).
 *
 * Read-only presentation of the current `KuzushiConfig` projected through
 * `shell.tuneSnapshot`. Each control renders as a labeled row with discrete
 * options (the active one bolded). The mapped config key is shown faintly
 * after the label, and the matching CLI flag on the right.
 *
 * Editing still flows through the full `ConfigEditor` — press `p` or type
 * `/config` to open it. This is the same escape hatch the v2 design calls
 * out as `prompt edit --expert`.
 */

import { Box, Text } from "ink";
import type React from "react";
import type { ShellState, TuneSnapshot } from "../state.js";
import { tokens } from "../tokens.js";
import { HouseRules } from "./HouseRules.js";
import { ShellFooterHints } from "./ShellFooterHints.js";

const PRESETS = ["fast", "standard", "deep"] as const;
const TASK_OPTIONS = ["semgrep", "codeql", "agentic", "iris-taint", "crypto-test"] as const;
const TRIAGE_LEVELS = [1, 3, 5, 10] as const;

interface TuneViewProps {
  shell: ShellState;
}

export function TuneView({ shell }: TuneViewProps): React.ReactElement {
  const moduleId = shell.focusedModule ?? "(no module)";
  const snap = shell.tuneSnapshot;

  return (
    <Box flexDirection="column" paddingLeft={2} marginBottom={1}>
      <Box>
        <Text>
          {tokens.muted("\u25C2 back   ")}
          {tokens.strong(moduleId)}
          {tokens.muted("   \u2502   ")}
          {tokens.muted("home   ")}
          {tokens.accent("tune")}
          {tokens.muted("    prompt    runs")}
        </Text>
      </Box>

      <TuneControl label="how hard should it hunt?" configKey="preset" flag="--preset <name>">
        <Options options={PRESETS} active={snap?.preset ?? "standard"} />
        <Text>
          {"    "}
          {tokens.muted("deep = verify + threat modeling + agentic detectors")}
        </Text>
      </TuneControl>

      <TuneControl label="which tasks?" configKey="tasks" flag="--tasks <ids,...>">
        <Options options={TASK_OPTIONS} active={snap?.tasks ?? []} multi />
        <Text>
          {"    "}
          {tokens.muted("codeql opt-in · requires the CodeQL CLI installed")}
        </Text>
      </TuneControl>

      <TuneControl label="prove it?" configKey="verify" flag="--verify">
        <Options options={["off", "verify"] as const} active={snap?.verify ? "verify" : "off"} />
        <Text>
          {"    "}
          {tokens.muted("constructs concrete exploits, runs in sandbox")}
        </Text>
      </TuneControl>

      <TuneControl label="auto-patch?" configKey="autoPatchEnabled" flag="--auto-patch">
        <Options options={["off", "on"] as const} active={snap?.autoPatch ? "on" : "off"} />
        <Text>
          {"    "}
          {tokens.muted("disposable worktrees · closed-loop re-verify")}
        </Text>
      </TuneControl>

      <TuneControl
        label="triage throughput"
        configKey="triageConcurrency"
        flag="config · default 5"
      >
        <Options
          options={TRIAGE_LEVELS.map((n) => String(n)) as readonly string[]}
          active={String(snap?.triageConcurrency ?? 5)}
        />
      </TuneControl>

      <TuneControl label="model" configKey="model" flag="--model <id>">
        <Text>
          {"    "}
          {tokens.strong(snap?.model ?? "(unset)")}
        </Text>
      </TuneControl>

      <Box marginTop={1}>
        <Text>{tokens.muted("\u2500".repeat(78))}</Text>
      </Box>

      <Box marginTop={1}>
        <HouseRules text={snap?.houseRules} path={snap?.houseRulesPath} />
      </Box>

      <Box marginTop={1}>
        <Text>{tokens.muted("\u2500".repeat(78))}</Text>
      </Box>

      <ShellFooterHints
        divider={false}
        hints={[
          { key: "s", label: "save" },
          { key: "r", label: "reset" },
          { key: "x", label: "run with these" },
          { key: "p", label: "full prompt editor (--expert)" },
          { key: "/config", label: "open editor" },
        ]}
      />
    </Box>
  );
}

function TuneControl({
  label,
  configKey,
  flag,
  children,
}: {
  label: string;
  configKey: keyof TuneSnapshot | string;
  flag?: string;
  children: React.ReactNode;
}): React.ReactElement {
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text>
        {tokens.label(label)}
        {"     "}
        {tokens.hint(String(configKey))}
        {flag ? tokens.muted(`    ${flag}`) : ""}
      </Text>
      <Box flexDirection="column" marginTop={1}>
        {children}
      </Box>
    </Box>
  );
}

function Options({
  options,
  active,
  multi,
}: {
  options: readonly string[];
  active: string | string[];
  multi?: boolean;
}): React.ReactElement {
  const activeSet = new Set(Array.isArray(active) ? active : [active]);
  const segs = options.map((opt) => {
    const on = activeSet.has(opt);
    const pretty = multi ? opt : opt;
    return on ? tokens.strong(pretty) : tokens.muted(pretty);
  });
  const sep = tokens.muted("  \u2500\u2500  ");
  return (
    <Text>
      {"    "}
      {segs.reduce<string>((acc, s, i) => (i === 0 ? s : acc + sep + s), "")}
    </Text>
  );
}
