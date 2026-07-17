import * as React from "react";
import { PHASE_META, cx } from "./shared.js";
import { PHASES, type PhaseRailProps, type PhaseState } from "./types.js";

const STATE_SYMBOL: Record<PhaseState, string> = {
  done: "✓",
  current: "●",
  failed: "!",
  skipped: "⊘",
  pending: "·",
};

export function PhaseRail({ current, statuses }: PhaseRailProps): React.ReactElement {
  const currentIndex = PHASES.indexOf(current);
  return (
    <div className="kz-phase-rail" aria-label={`Workflow phase: ${PHASE_META[current].label}`}>
      {PHASES.map((phase, index) => {
        const state = statuses?.[phase] ?? (index < currentIndex ? "done" : index === currentIndex ? "current" : "pending");
        return (
          <React.Fragment key={phase}>
            {index > 0 && <span className="kz-rail-separator">·</span>}
            <span className={cx("kz-rail-phase", `kz-phase-${phase}`, `kz-state-${state}`)}>
              {PHASE_META[phase].kanji}  {PHASE_META[phase].label.toLowerCase()} {STATE_SYMBOL[state]}
            </span>
          </React.Fragment>
        );
      })}
    </div>
  );
}
