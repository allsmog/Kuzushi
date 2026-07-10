import type { ReactNode } from "react";

export interface CockpitPaneProps {
  /** Pane title, shown on the rail (e.g. `SOURCE · 42 files`, `REVIEW QUEUE`). */
  title: string;
  /** Light the rail + title accent to mark the focused pane. */
  focused?: boolean;
  /** Pane body — {@link Row}/{@link LogLine}/{@link ReviewQueueRow} content. */
  children: ReactNode;
}

/**
 * The Atlas cockpit pane chrome — one stable vertical rail down the left edge
 * with the title sitting on it, mirroring the Rust `cockpit_pane_block`. It is
 * deliberately NOT a full box: the workbench tiles several of these side by
 * side (SOURCE · CENTER · FINDINGS · DETAILS) and a single left rail per pane
 * keeps the grid calm. The focused pane lights its rail and title accent; the
 * rest stay subtle + muted. Stack {@link Row}s or {@link ReviewQueueRow}s inside.
 *
 * @example
 * <CockpitPane title="REVIEW QUEUE · 3" focused>
 *   <ReviewQueueRow alias="F-0012" severity="critical" proof="confirmed" title="sql injection" selected />
 *   <ReviewQueueRow alias="F-0007" severity="high" proof="likely" title="path traversal" />
 * </CockpitPane>
 */
export function CockpitPane({ title, focused, children }: CockpitPaneProps) {
  return (
    <div className={focused ? "kz-pane kz-pane--focused" : "kz-pane"}>
      <div className="kz-pane__title">{title}</div>
      {children}
    </div>
  );
}
