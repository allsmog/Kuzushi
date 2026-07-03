import { Fragment } from "react";
import { Glyph } from "./Glyph";
import { Row } from "./Row";

export interface EngineChip {
  /** Engine name (e.g. `cpg`, `codeql`, `lsp`). */
  name: string;
  /** Whether it is enabled for this scan. */
  on: boolean;
  /** Optional cost/latency estimate shown when enabled (e.g. `~40s`). */
  cost?: string;
}

export interface EngineChipsProps {
  /** Leading label (default `engines`). */
  label?: string;
  /** The analysis engines and their per-scan enablement. */
  engines: EngineChip[];
  /** Fix the row to a grid width in cells. */
  cols?: number;
}

/**
 * The per-scan engine-enablement row — the control plane's analysis toggles.
 * Each chip is an oracle you turn on for this pass (`cpg ✓`, `codeql ○`,
 * `lsp ○`): enabled reads primary + ✓ with an optional cost estimate, disabled
 * reads muted + ○. Enablement stays honest — a heavyweight engine shows its cost
 * before you commit it.
 *
 * @example
 * <EngineChips cols={56} engines={[
 *   { name: "cpg", on: true, cost: "~40s" },
 *   { name: "codeql", on: false },
 *   { name: "lsp", on: false },
 * ]} />
 */
export function EngineChips({ label = "engines", engines, cols }: EngineChipsProps) {
  return (
    <Row cols={cols}>
      {" "}
      <Glyph tone="muted">{`${label}  `}</Glyph>
      {engines.map((e, i) => (
        <Fragment key={e.name}>
          <Glyph tone={e.on ? "primary" : "muted"}>{e.name}</Glyph>{" "}
          <Glyph tone={e.on ? "success" : "subtle"}>{e.on ? "✓" : "○"}</Glyph>
          {e.on && e.cost ? <Glyph tone="subtle">{` ${e.cost}`}</Glyph> : null}
          {i !== engines.length - 1 ? <Glyph tone="subtle">{"   "}</Glyph> : null}
        </Fragment>
      ))}
    </Row>
  );
}
