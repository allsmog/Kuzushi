import type { CSSProperties, ReactNode } from "react";

export interface TermFrameProps {
  /** Title shown in the window chrome (e.g. `kuzushi · sast`). */
  title?: string;
  /**
   * Grid width in monospace cells. Sizes the terminal body to a fixed column
   * count (the real shell runs at 120). Omit to let the frame fill its
   * container.
   */
  cols?: number;
  /** Hide the macOS traffic-light window chrome. */
  chromeless?: boolean;
  /** Terminal content — {@link Row}, {@link StatusStrip}, {@link LogLine}, etc. */
  children: ReactNode;
}

/**
 * The terminal window: a rounded dark frame with macOS traffic-light chrome
 * and a monospace body. Every Kuzushi screen lives inside one. Stack
 * {@link StatusStrip}, {@link SectionHeader}, {@link Row}/{@link LogLine}
 * content, and a {@link Footer} as children to build a full view.
 *
 * @example
 * <TermFrame title="kuzushi · sast" cols={96}>
 *   <StatusStrip target="~/work/acme-checkout" module="sast" cost="$0.41" />
 *   <Row> </Row>
 *   <LogLine kind="ok" time="14:31:55"> semgrep · 612/612 · done</LogLine>
 * </TermFrame>
 */
export function TermFrame({ title, cols, chromeless, children }: TermFrameProps) {
  const fluid = cols == null;
  // The body is border-box with 14px of horizontal padding each side; add it
  // back so the content grid is exactly `cols` monospace cells wide and a
  // full-width Row/StatusStrip lands flush instead of clipping.
  const bodyStyle: CSSProperties | undefined =
    cols != null ? { width: `calc(${cols}ch + 28px)` } : undefined;
  return (
    <div className={fluid ? "kz-frame kz-frame--fluid" : "kz-frame"}>
      {!chromeless && (
        <div className="kz-chrome">
          <div className="kz-dot kz-dot--r" />
          <div className="kz-dot kz-dot--y" />
          <div className="kz-dot kz-dot--g" />
          {title != null && <div className="kz-chrome__title">{title}</div>}
        </div>
      )}
      <div className="kz-term" style={bodyStyle}>
        {children}
      </div>
    </div>
  );
}
