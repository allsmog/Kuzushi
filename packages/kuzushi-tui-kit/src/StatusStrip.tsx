import { Glyph } from "./Glyph";
import { Row } from "./Row";

export interface StatusStripProps {
  /** Active scan target path. */
  target: string;
  /** Context-freshness label (e.g. `fresh (3m ago)`). */
  ctx?: string;
  /** Configured agent model (e.g. `openai:gpt-4.1`). */
  model?: string;
  /** Active module, or `—` when none is selected. */
  module?: string;
  /** Running cost for the turn (e.g. `$0.41`). */
  cost?: string;
  /** Fix the strip to a grid width in cells. */
  cols?: number;
}

/**
 * The top status strip present on every screen: the `KUZUSHI` wordmark plus
 * labeled `target / ctx / model / module / cost` fields. It is the operator's
 * always-visible orientation line — what am I scanning, with which model, at
 * what cost.
 *
 * @example
 * <StatusStrip target="~/work/acme-checkout" ctx="fresh" module="sast" cost="$0.41" />
 */
export function StatusStrip({
  target,
  ctx = "fresh (3m ago)",
  model = "openai:gpt-4.1",
  module = "—",
  cost = "$0.00",
  cols,
}: StatusStripProps) {
  return (
    <Row cols={cols}>
      {" "}
      <Glyph tone="heading">KUZUSHI</Glyph>
      {"  "}
      <Glyph tone="muted">target </Glyph>
      <Glyph tone="primary">{target}</Glyph>
      {"  "}
      <Glyph tone="muted">ctx </Glyph>
      <Glyph tone="success">✓ </Glyph>
      <Glyph tone="primary">{ctx}</Glyph>
      {"  "}
      <Glyph tone="muted">model </Glyph>
      <Glyph tone="primary">{model}</Glyph>
      {"  "}
      <Glyph tone="muted">module </Glyph>
      <Glyph tone={module === "—" ? "muted" : "accent"}>{module}</Glyph>
      {"  "}
      <Glyph tone="muted">cost </Glyph>
      <Glyph tone="primary">{cost}</Glyph>
    </Row>
  );
}
