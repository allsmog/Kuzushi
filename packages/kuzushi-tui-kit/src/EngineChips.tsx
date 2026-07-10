import { Fragment } from "react";
import { Glyph } from "./Glyph";
import { Row } from "./Row";

/**
 * An analysis engine's readiness for this scan, mirroring the Rust hunt-pane
 * chips: `ready` (✓, warmed and usable), `build` (○, needs a CPG/DB build
 * first), or `opt-in` (○, available but off until you enable it).
 */
export type EngineState = "ready" | "build" | "opt-in";

export interface EngineChip {
  /** Engine name (e.g. `cpg`, `codeql`, `lsp`). */
  name: string;
  /** Readiness state — sets the glyph, tone, and trailing word. */
  state: EngineState;
  /** Optional cost/latency estimate shown when ready (e.g. `~40s`). */
  cost?: string;
}

const STATE: Record<EngineState, { glyph: string }> = {
  ready: { glyph: "✓" },
  build: { glyph: "○" },
  "opt-in": { glyph: "○" },
};

export interface EngineChipsProps {
  /** Leading label (default `engines`). */
  label?: string;
  /** The analysis engines and their per-scan readiness. */
  engines: EngineChip[];
  /** Fix the row to a grid width in cells. */
  cols?: number;
}

/**
 * The per-scan engine-readiness row — the control plane's analysis oracles.
 * Each chip shows an engine and where it stands for this pass, exactly like the
 * Rust hunt pane: `cpg ✓ ready` (success), `codeql ○ build` (muted, needs a CPG
 * build), `lsp ○ opt-in` (muted, available but off). Readiness stays honest — a
 * heavyweight engine shows `build` (and its cost) before you commit it, so you
 * never fire a scan expecting an oracle that isn't warmed.
 *
 * @example
 * <EngineChips cols={56} engines={[
 *   { name: "cpg", state: "ready", cost: "~40s" },
 *   { name: "codeql", state: "build" },
 *   { name: "lsp", state: "opt-in" },
 * ]} />
 */
export function EngineChips({ label = "engines", engines, cols }: EngineChipsProps) {
  return (
    <Row cols={cols}>
      {" "}
      <Glyph tone="muted">{`${label}  `}</Glyph>
      {engines.map((e, i) => {
        const ready = e.state === "ready";
        return (
          <Fragment key={e.name}>
            <Glyph tone={ready ? "primary" : "muted"}>{e.name}</Glyph>{" "}
            <Glyph tone={ready ? "success" : "subtle"}>{STATE[e.state].glyph}</Glyph>{" "}
            <Glyph tone={ready ? "success" : "muted"}>{e.state}</Glyph>
            {ready && e.cost ? <Glyph tone="subtle">{` ${e.cost}`}</Glyph> : null}
            {i !== engines.length - 1 ? <Glyph tone="subtle">{"   "}</Glyph> : null}
          </Fragment>
        );
      })}
    </Row>
  );
}
