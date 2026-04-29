/**
 * ContextBuildView — Live Build screen for `/context build`.
 *
 * Renders the five phases of the deterministic `gatherContextForRoot`
 * pipeline (manifests → walk → path signals → grep sweep → assemble),
 * plus a pillar preview that fills in as signals land, plus a tail log
 * of the most recent observer events. Driven by `shell.contextBuild`
 * (see `ContextBuildState`); mutations come from the phase observer in
 * `runContextBuildLive`.
 *
 * Frame chrome (`╭─ Phases ─╮ / ╰─╯`) is drawn via the shared
 * `boxHeader`/`boxFooter` helpers in `src/ui/format.ts` so this screen
 * matches the framing used by `ConfigBanner`, `SectionBox`, etc.
 */

import { Box, Text } from "ink";
import type React from "react";
import { boxFooter, boxHeader } from "../format.js";
import { useRegisterKeybindings } from "../hooks/useKeybindings.js";
import { useElapsed, useTerminalWidth } from "../hooks.js";
import type { ContextBuildGrepDomainSlice, ContextBuildState, ShellState } from "../state.js";
import { SPACING, tokens } from "../tokens.js";
import { ContextStrip } from "./ContextStrip.js";
import { DelayedBusyIndicator } from "./DelayedBusyIndicator.js";
import { ScreenContent } from "./ScreenContent.js";

const PHASE_ROWS: ReadonlyArray<{
  id: "manifests" | "walk" | "path-signals" | "grep" | "assemble";
  num: string;
  title: string;
  /** Hint shown on the phase row itself — beside the status cell. */
  hint: (state: ContextBuildState) => string;
}> = [
  {
    id: "manifests",
    num: "1.",
    title: "manifest probes",
    hint: () => "5 in parallel",
  },
  {
    id: "walk",
    num: "2.",
    title: "walk repo",
    hint: () => "depth≤5 · capped at 4000",
  },
  {
    id: "path-signals",
    num: "3.",
    title: "path signals",
    hint: (s) => (s.pathSignals.length > 0 ? s.pathSignals.join(", ") : "scanning paths"),
  },
  {
    id: "grep",
    num: "4.",
    title: "grep sweep",
    hint: (s) =>
      s.grep
        ? `${(s.grep.domains ?? []).length} domains · ${s.grep.workers} workers`
        : "8 domains · 16 workers",
  },
  {
    id: "assemble",
    num: "5.",
    title: "assemble + write .kuzushi/scan-context.json",
    hint: () => "",
  },
];

const MANIFEST_LABELS: ReadonlyArray<{
  key: "package.json" | "go.mod" | "pyproject" | "Cargo.toml" | "native-build";
  label: string;
}> = [
  { key: "package.json", label: "package.json" },
  { key: "go.mod", label: "go.mod" },
  { key: "pyproject", label: "pyproject" },
  { key: "Cargo.toml", label: "Cargo.toml" },
  { key: "native-build", label: "CMakeLists / Makefile" },
];

const TAIL_COLLAPSED_LIMIT = 5;
const TAIL_EXPANDED_LIMIT = 60;

// Column layout inside the phases box, relative to the `glyph num` prefix.
// TITLE_COL matches the design: `manifest probes          done` lands `done`
// about 28 cols after the left frame edge.
const TITLE_COL = 24;
const STATUS_COL = 8;

interface ContextBuildViewProps {
  shell: ShellState;
}

export function ContextBuildView({ shell }: ContextBuildViewProps): React.ReactElement {
  const contextBuildStatus = shell.contextBuild?.status;
  useRegisterKeybindings([
    { keys: "q", label: contextBuildStatus === "running" ? "abort" : "back" },
    { keys: "L", label: "expand tail", secondary: true },
  ]);
  const terminalWidth = useTerminalWidth();
  const frameWidth = Math.max(60, Math.min(terminalWidth - 4, 82));

  const cb = shell.contextBuild;
  if (!cb) {
    return (
      <ScreenContent>
        <Text>{tokens.hint("No build in progress. Run /context build to start.")}</Text>
      </ScreenContent>
    );
  }

  // Pillar preview renders as a 2-column grid; give each column half the
  // frame width minus a gap so long values don't wrap mid-word.
  const pillarColWidth = Math.max(32, Math.floor((frameWidth - 2) / 2));

  return (
    <ScreenContent>
      <HeaderStrip state={cb} />
      {cb.status === "running" ? (
        <DelayedBusyIndicator
          label="Building context"
          detail={currentContextBuildDetail(cb)}
          startedAt={cb.startedAtMs}
          delayMs={0}
        />
      ) : null}
      <PhasesBox state={cb} width={frameWidth} />
      <PillarPreview state={cb} colWidth={pillarColWidth} />
      <TailLog state={cb} />
      <ControlBar state={cb} width={frameWidth} />
    </ScreenContent>
  );
}

function currentContextBuildDetail(state: ContextBuildState): string {
  const running = PHASE_ROWS.find((phase) => state.phases[phase.id].status === "running");
  if (!running) return "Waiting for the first phase event.";
  return `${running.title} · ${running.hint(state)}`.replace(/\s+·\s*$/, "");
}

function HeaderStrip({ state }: { state: ContextBuildState }): React.ReactElement {
  const elapsedMs = useElapsed(state.startedAtMs, state.status === "running" ? 1000 : 5000);
  const statusLabel =
    state.status === "running"
      ? `building · ${formatMmSs(elapsedMs)}`
      : state.status === "done"
        ? `done · ${formatMmSs(elapsedMs)}`
        : state.status === "aborted"
          ? "aborted"
          : "failed";
  const startedClock = formatClock(state.startedAtMs);
  return (
    <ContextStrip
      status={[statusLabel, `run ${state.runId}`, `started ${startedClock}`]}
      subtitle={`building OperatorScanContext from ${state.repoRoot}`}
    />
  );
}

// ── Phase tracker ──────────────────────────────────────────────────────────
//
// Pixel-matched to the design: every inner row is wrapped `│  …  │` so the
// phase box reads as one solid frame. `frameLine(content, width)` measures
// printable length (ignoring ANSI) and right-pads before the closing `│`.

function PhasesBox({
  state,
  width,
}: {
  state: ContextBuildState;
  width: number;
}): React.ReactElement {
  const lines: string[] = [];
  lines.push(frameBlank(width));
  for (let i = 0; i < PHASE_ROWS.length; i++) {
    const phase = PHASE_ROWS[i];
    const slice = state.phases[phase.id];
    const glyph = phaseGlyph(slice.status);
    const paddedTitle = padEndPlain(phase.title, TITLE_COL);
    const paddedStatus = padEndColored(phaseStatusLabel(slice), STATUS_COL);
    const baseHint = phase.hint(state);
    const hintText =
      slice.status === "done" && slice.durationMs != null
        ? baseHint
          ? `${baseHint} · ${formatDurationMs(slice.durationMs)}`
          : formatDurationMs(slice.durationMs)
        : baseHint;
    const hint = hintText ? tokens.hint(hintText) : "";
    lines.push(
      frameRow(
        ` ${glyph.render} ${tokens.muted(phase.num)} ${tokens.strong(paddedTitle)} ${paddedStatus} ${hint}`,
        width,
      ),
    );
    const detailLines = phaseDetailLines(phase.id, state);
    for (const detail of detailLines) lines.push(frameRow(`      ${detail}`, width));
    if (i < PHASE_ROWS.length - 1) lines.push(frameBlank(width));
  }
  lines.push(frameBlank(width));
  return (
    <Box flexDirection="column" marginBottom={SPACING.sm}>
      <Text>{boxHeader("Phases", width)}</Text>
      {lines.map((line, i) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: rows are positional, order doesn't change between renders
        <Text key={i}>{line}</Text>
      ))}
      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}

function phaseDetailLines(
  id: (typeof PHASE_ROWS)[number]["id"],
  state: ContextBuildState,
): string[] {
  switch (id) {
    case "manifests":
      return manifestDetailLines(state);
    case "walk":
      return walkDetailLines(state);
    case "path-signals":
      return pathSignalsDetailLines(state);
    case "grep":
      return grepDetailLines(state);
    default:
      return [];
  }
}

function manifestDetailLines(state: ContextBuildState): string[] {
  if (state.phases.manifests.status === "pending") return [];
  const row1 = MANIFEST_LABELS.slice(0, 3);
  const row2 = MANIFEST_LABELS.slice(3);
  return [
    row1.map((p) => formatManifestCell(p.label, state.manifests[p.key])).join("   "),
    row2.map((p) => formatManifestCell(p.label, state.manifests[p.key])).join("   "),
  ];
}

function formatManifestCell(label: string, result: "found" | "miss" | undefined): string {
  return `${tokens.hint(label)}  ${manifestGlyph(result)}`;
}

function walkDetailLines(state: ContextBuildState): string[] {
  if (state.phases.walk.status === "pending" || !state.walk) return [];
  const { entries, dirs, sourceFiles, cap } = state.walk;
  const underCap = entries < cap;
  const row1 =
    tokens.muted("entries ") +
    tokens.value(formatInt(entries)) +
    tokens.muted(` / ${formatInt(cap)}`) +
    "     " +
    tokens.muted("dirs ") +
    tokens.value(formatInt(dirs)) +
    "     " +
    tokens.muted("source files ") +
    tokens.value(formatInt(sourceFiles));
  const bar = tokens.success(progressBar(entries, cap, 10));
  const row2 =
    bar +
    "  " +
    tokens.hint(
      underCap ? "well under cap — fileIndex not truncated" : "at cap — fileIndex truncated",
    );
  return [row1, row2];
}

function pathSignalsDetailLines(_state: ContextBuildState): string[] {
  // Path signals render inline in the phase-row hint. The design has no
  // secondary detail row for this phase.
  return [];
}

function grepDetailLines(state: ContextBuildState): string[] {
  if (state.phases.grep.status === "pending") return [];
  const grep = state.grep;
  if (!grep) return [];
  const lines: string[] = [];
  lines.push(
    tokens.muted("file ") +
      tokens.value(formatInt(grep.filesDone)) +
      tokens.muted(" / " + formatInt(grep.filesTotal)),
  );
  lines.push(
    tokens.accent(progressBar(grep.filesDone, grep.filesTotal, 10)) +
      "  " +
      tokens.hint("under-size cap 100KB; large files skipped"),
  );
  lines.push("");
  lines.push(
    tokens.hint(padEndPlain("domain", 22)) +
      tokens.hint(padEndPlain("matches", 14)) +
      tokens.hint("status"),
  );
  for (const domain of grep.domains) {
    const matchesCell =
      domain.status === "capped"
        ? tokens.warn(`${domain.matches} / ${grep.domainCap}`)
        : tokens.value(padStartPlain(String(domain.matches), 3));
    lines.push(
      padEndColored(tokens.muted(domain.name), 22) +
        padEndColored(matchesCell, 14) +
        domainStatusLabel(domain.status),
    );
  }
  return lines;
}

// ── Pillar preview ─────────────────────────────────────────────────────────

function PillarPreview({
  state,
  colWidth,
}: {
  state: ContextBuildState;
  colWidth: number;
}): React.ReactElement {
  const { architecture, trust } = state.pillars;
  const grepRunning = state.phases.grep.status === "running";
  const archRows: PillarRowSpec[] = [
    { label: "languages", value: architecture.languages },
    { label: "frameworks", value: architecture.frameworks },
    { label: "entry points", value: architecture.entryPoints },
    {
      label: "data flows",
      placeholder: grepRunning ? "waiting on grep…" : "waiting on enrichment",
    },
    { label: "external deps", value: architecture.ormOrDb, placeholder: "waiting on enrichment" },
  ];
  const trustRows: PillarRowSpec[] = [
    { label: "external defenses", value: trust.sanitizationLibs },
    { label: "auth patterns", value: trust.authPatterns },
    { label: "sanitization libs", value: trust.sanitizationLibs },
  ];
  const scopeRows: PillarRowSpec[] = [
    { label: "high-value assets", placeholder: "not auto-detected" },
    { label: "sensitive data", placeholder: "not auto-detected" },
  ];
  const histRows: PillarRowSpec[] = [
    { label: "suppressed fp", placeholder: "waiting on verdict-bridge…" },
    { label: "confirmed tp", placeholder: "waiting on verdict-bridge…" },
  ];

  return (
    <Box flexDirection="column" marginBottom={SPACING.sm}>
      <Text>
        {tokens.label("Pillar preview")}
        {"   "}
        {tokens.hint("filling in as signals land — all items will land as ")}
        {tokens.muted("[ skipped ]")}
      </Text>
      <Text> </Text>
      <Box flexDirection="row">
        <Box flexDirection="column" width={colWidth} marginRight={2}>
          <Text>{tokens.label("ARCHITECTURE")}</Text>
          {renderPillarRows(archRows, colWidth)}
        </Box>
        <Box flexDirection="column" width={colWidth}>
          <Text>{tokens.label("TRUST")}</Text>
          {renderPillarRows(trustRows, colWidth)}
        </Box>
      </Box>
      <Text> </Text>
      <Box flexDirection="row">
        <Box flexDirection="column" width={colWidth} marginRight={2}>
          <Text>{tokens.label("SCOPE")}</Text>
          {renderPillarRows(scopeRows, colWidth)}
        </Box>
        <Box flexDirection="column" width={colWidth}>
          <Text>{tokens.label("HISTORICAL")}</Text>
          {renderPillarRows(histRows, colWidth)}
        </Box>
      </Box>
      <Box marginTop={SPACING.sm}>
        <Text>{tokens.hint("(scope / historical fed by findings cache, not this run)")}</Text>
      </Box>
    </Box>
  );
}

interface PillarRowSpec {
  label: string;
  value?: ReadonlyArray<string>;
  placeholder?: string;
}

const PILLAR_LABEL_WIDTH = 18;

function renderPillarRows(
  rows: ReadonlyArray<PillarRowSpec>,
  colWidth: number,
): React.ReactElement[] {
  // Value-cell width = column total − prefix("├ ") − label − " " separator.
  const valueWidth = Math.max(8, colWidth - 2 - PILLAR_LABEL_WIDTH - 1);
  return rows.map((row, idx) => {
    const isLast = idx === rows.length - 1;
    const prefix = isLast ? "└" : "├";
    const hasValue = row.value && row.value.length > 0;
    const raw = hasValue
      ? row.value!.slice(0, 3).join(" · ") +
        (row.value!.length > 3 ? ` · +${row.value!.length - 3}` : "")
      : (row.placeholder ?? "waiting…");
    const shown = truncateToWidth(raw, valueWidth);
    return (
      <Text key={row.label}>
        {tokens.muted(`${prefix} ${padEndPlain(row.label, PILLAR_LABEL_WIDTH)}`)}{" "}
        {hasValue ? tokens.value(shown) : tokens.hint(shown)}
      </Text>
    );
  });
}

function truncateToWidth(value: string, width: number): string {
  if (value.length <= width) return value;
  return value.slice(0, Math.max(0, width - 1)) + "…";
}

// ── Tail log ───────────────────────────────────────────────────────────────

function TailLog({ state }: { state: ContextBuildState }): React.ReactElement {
  const limit = state.tailExpanded ? TAIL_EXPANDED_LIMIT : TAIL_COLLAPSED_LIMIT;
  const lines = state.tail.slice(-limit);
  const shown = Math.min(limit, state.tail.length);
  return (
    <Box flexDirection="column" marginBottom={SPACING.sm}>
      <Text>
        {tokens.label("Tail")}
        {"   "}
        {tokens.hint(
          state.tailExpanded
            ? `full log (${state.tail.length}) · press `
            : `last ${shown} line${shown === 1 ? "" : "s"} · press `,
        )}
        {tokens.strong("L")}
        {tokens.hint(state.tailExpanded ? " to collapse" : " to expand full log")}
      </Text>
      <Text> </Text>
      {lines.length === 0 ? (
        <Text>{tokens.hint("  (waiting on first event)")}</Text>
      ) : (
        lines.map((line, i) => (
          <Text key={`${line.tsMs}-${i}`}>
            {"  "}
            {tokens.subtle(formatTimeStampMs(line.tsMs))}
            {"  "}
            {line.kind === "warn" ? tokens.warn(line.message) : tokens.muted(line.message)}
          </Text>
        ))
      )}
    </Box>
  );
}

// ── Control bar ────────────────────────────────────────────────────────────

function ControlBar({
  state,
  width,
}: {
  state: ContextBuildState;
  width: number;
}): React.ReactElement {
  const prompt =
    state.status === "running"
      ? `${tokens.strong("q")} abort      ${tokens.strong("L")} expand tail`
      : `${tokens.strong("q")} back      ${tokens.strong("L")} expand tail`;
  const hint =
    state.status === "running"
      ? "safe to walk away — no writes until phase 5 (assemble)"
      : state.status === "done"
        ? `context saved to ${state.scanContextPath ?? ".kuzushi/scan-context.json"}`
        : state.status === "aborted"
          ? "aborted — no snapshot written"
          : `failed${state.errorMessage ? " — " + state.errorMessage : ""}`;
  return (
    <Box flexDirection="column">
      <Text>{framePlainTop(width)}</Text>
      <Text>{frameRow(` ${prompt}`, width)}</Text>
      <Text>{frameRow(` ${tokens.hint(hint)}`, width)}</Text>
      <Text>{boxFooter(width)}</Text>
    </Box>
  );
}

// ── Pure helpers (exported for tests) ──────────────────────────────────────

export type PhaseStatus = ContextBuildState["phases"][keyof ContextBuildState["phases"]]["status"];

export function phaseGlyph(status: PhaseStatus): { render: string; plain: string } {
  switch (status) {
    case "done":
      return { render: tokens.successStrong("✓"), plain: "✓" };
    case "running":
      return { render: tokens.warnStrong("▸"), plain: "▸" };
    case "failed":
      return { render: tokens.dangerStrong("✗"), plain: "✗" };
    default:
      return { render: tokens.subtle("○"), plain: "○" };
  }
}

export function phaseStatusLabel(slice: { status: PhaseStatus; durationMs?: number }): string {
  switch (slice.status) {
    case "done":
      return tokens.success("done");
    case "running":
      return tokens.warn("running");
    case "failed":
      return tokens.danger("failed");
    default:
      return tokens.subtle("pending");
  }
}

export function manifestGlyph(result: "found" | "miss" | undefined): string {
  if (result === "found") return tokens.success("✓");
  if (result === "miss") return tokens.subtle("—");
  return tokens.subtle("·");
}

export function domainStatusLabel(status: ContextBuildGrepDomainSlice["status"]): string {
  switch (status) {
    case "active":
      return tokens.success("active");
    case "capped":
      return tokens.warn("capped — this is fine");
    case "skipped-no-ext":
      return tokens.hint("skipped (no matching ext)");
    default:
      return tokens.subtle("pending");
  }
}

/**
 * Unicode block progress bar of a fixed number of cells. Always emits
 * `width` characters so rows stay aligned even at 0% or 100%.
 */
export function progressBar(done: number, total: number, width: number): string {
  if (width <= 0) return "";
  if (total <= 0) return "▱".repeat(width);
  const clamped = Math.max(0, Math.min(done, total));
  const filled = Math.round((clamped / total) * width);
  return "▰".repeat(filled) + "▱".repeat(width - filled);
}

export function formatMmSs(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const m = Math.floor(total / 60);
  const s = total % 60;
  return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
}

export function formatDurationMs(ms: number): string {
  // Design uses second-format throughout (`0.14s`, `1.2s`, `12.3s`) rather
  // than mixing ms + s. Match that — it reads as one consistent time scale.
  const secs = ms / 1000;
  if (secs < 10) return `${secs.toFixed(2)}s`;
  if (secs < 100) return `${secs.toFixed(1)}s`;
  return `${Math.round(secs)}s`;
}

function formatInt(n: number): string {
  // Narrow-space thousands grouping — mirrors the design's "1 847".
  return n.toLocaleString("en-US").replace(/,/g, " ");
}

function formatClock(ms: number): string {
  const d = new Date(ms);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}`;
}

function formatTimeStampMs(ms: number): string {
  const d = new Date(ms);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const millis = String(d.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${millis}`;
}

function padEndPlain(value: string, width: number): string {
  return value.length >= width ? value : value + " ".repeat(width - value.length);
}

function padStartPlain(value: string, width: number): string {
  return value.length >= width ? value : " ".repeat(width - value.length) + value;
}

/**
 * Pad a possibly-chalk-colored string to `width` printable columns. The
 * padding is plain spaces outside the escape codes, so alignment survives
 * even when the cell contents are wrapped in ANSI SGR sequences.
 */
function padEndColored(value: string, width: number): string {
  const printable = stripAnsi(value);
  const pad = Math.max(0, width - printable.length);
  return value + " ".repeat(pad);
}

function stripAnsi(s: string): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: strip chalk escape sequences
  return s.replace(/\[[0-9;]*m/g, "");
}

// ── Custom frame helpers (side-bar framing) ────────────────────────────────
// `boxHeader`/`boxFooter` draw the top/bottom edges but don't wrap inner
// rows. These three helpers produce `│ <content pad-to-inner-width> │` rows
// so the rendered output matches the design's solid-frame phase box and
// control bar exactly.

const FRAME_VERTICAL = "│";
const FRAME_HORIZONTAL = "─";
const FRAME_TL = "╭";
const FRAME_TR = "╮";

function innerWidth(frameWidth: number): number {
  // -2 for the side bars; -2 more for the single-space breathing-room on each side.
  return Math.max(0, frameWidth - 4);
}

function frameRow(content: string, frameWidth: number): string {
  const inner = innerWidth(frameWidth);
  const printable = stripAnsi(content).length;
  const pad = Math.max(0, inner - printable);
  const bar = tokens.metadata(FRAME_VERTICAL);
  return `${bar} ${content}${" ".repeat(pad)} ${bar}`;
}

function frameBlank(frameWidth: number): string {
  const inner = innerWidth(frameWidth);
  const bar = tokens.metadata(FRAME_VERTICAL);
  return `${bar} ${" ".repeat(inner)} ${bar}`;
}

function framePlainTop(frameWidth: number): string {
  const inner = innerWidth(frameWidth) + 2;
  return tokens.metadata(`${FRAME_TL}${FRAME_HORIZONTAL.repeat(inner)}${FRAME_TR}`);
}
