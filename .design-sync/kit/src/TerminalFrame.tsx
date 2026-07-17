import * as React from "react";
import { cx, terminalStyle } from "./shared.js";
import type { TerminalFrameProps } from "./types.js";

/**
 * Neutral terminal capture frame. Kuzushi's own TUI begins inside the body;
 * this wrapper intentionally has no decorative traffic-light controls.
 */
export function TerminalFrame({
  title = "kuzushi",
  cols = 80,
  rows = 24,
  chromeless = false,
  children,
}: TerminalFrameProps): React.ReactElement {
  return (
    <section
      className={cx("kz-terminal", chromeless && "kz-terminal-chromeless")}
      style={terminalStyle(cols, rows)}
      aria-label={`${title} terminal at ${cols} by ${rows}`}
    >
      {!chromeless && (
        <div className="kz-capture-bar">
          <span>{title}</span>
          <span>{cols}×{rows}</span>
        </div>
      )}
      <div className="kz-terminal-body">{children}</div>
    </section>
  );
}
