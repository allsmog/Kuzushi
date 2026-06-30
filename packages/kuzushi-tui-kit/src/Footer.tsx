import { Fragment } from "react";
import { Glyph } from "./Glyph";
import { Row } from "./Row";
import { DEFAULT_COLS } from "./tokens";

export interface Keybind {
  /** The key or verb (e.g. `/findings`, `j/k`, `Ctrl+C`). */
  key: string;
  /** What the key does (e.g. `browse`). */
  hint: string;
}

export interface FooterProps {
  /** The current stage label shown left of the status line. */
  stage?: string;
  /** Findings count shown on the right (primary when > 0). */
  findings?: number;
  /** Module name for the prompt (`kuzushi (sast)>`); omit for `kuzushi>`. */
  module?: string;
  /** Keybind contract for this view, rendered on the verbs line. */
  keybinds?: Keybind[];
  /** Grid width in cells used to justify the status line and rule. */
  cols?: number;
}

/**
 * The bottom strip: a rule, a stage/findings status line, the keybind contract
 * for the current view, and the input prompt with a block cursor. The keybind
 * line is the operator's contract — what works on this view is always visible.
 *
 * @example
 * <Footer
 *   stage="sast:scan · agentic 73%"
 *   findings={11}
 *   module="sast"
 *   keybinds={[{ key: "/findings", hint: "browse" }, { key: "/open", hint: "F-0001" }]}
 * />
 */
export function Footer({
  stage = "idle",
  findings = 0,
  module,
  keybinds = [],
  cols = DEFAULT_COLS,
}: FooterProps) {
  const left = ` stage ${stage} · routing direct`;
  const right = `Ctrl+C quit · findings ${findings} `;
  const pad = " ".repeat(Math.max(1, cols - left.length - right.length));
  const prompt = module ? ` kuzushi (${module})> ` : " kuzushi> ";
  return (
    <>
      <Row tone="subtle">{"─".repeat(cols)}</Row>
      <Row>
        <Glyph tone="muted">{left}</Glyph>
        {pad}
        <Glyph tone="muted">Ctrl+C quit · findings </Glyph>
        <Glyph tone={findings > 0 ? "primary" : "muted"}>{String(findings)}</Glyph>{" "}
      </Row>
      <Row>
        {" "}
        {keybinds.map((kb, i) => (
          <Fragment key={kb.key}>
            <Glyph tone="accent">{kb.key}</Glyph>{" "}
            <Glyph tone="muted">{kb.hint}</Glyph>
            {i !== keybinds.length - 1 ? "   " : null}
          </Fragment>
        ))}
      </Row>
      <Row>
        <Glyph tone="muted">{prompt}</Glyph>
        <Glyph tone="selection"> </Glyph>
      </Row>
    </>
  );
}
