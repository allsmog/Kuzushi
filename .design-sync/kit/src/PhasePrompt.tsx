import * as React from "react";
import { KeyHints, PHASE_META, cx } from "./shared.js";
import type { PhasePromptProps } from "./types.js";

export function PhasePrompt({
  phase,
  value = "",
  placeholder,
  mode = "prompt",
  notice,
  hints,
}: PhasePromptProps): React.ReactElement {
  const meta = PHASE_META[phase];
  return (
    <footer className={cx("kz-phase-prompt", `kz-phase-${phase}`, mode === "navigate" && "kz-prompt-navigate")}>
      {notice && <div className="kz-prompt-notice">{notice}</div>}
      <KeyHints hints={hints} />
      {mode === "navigate" ? (
        <div className="kz-navigate-label"><strong>{meta.token} {meta.label} › </strong>NAVIGATE · Shift+Tab mode · Tab/[/] pane · Esc prompt</div>
      ) : (
        <div className="kz-composer-line">
          <strong>{meta.token} {meta.label} › </strong>
          {value ? <span className="kz-composer-value">{value}</span> : <span className="kz-placeholder">{placeholder ?? meta.placeholder}</span>}
          <span className="kz-cursor" aria-hidden="true"> </span>
        </div>
      )}
    </footer>
  );
}
