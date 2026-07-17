import * as React from "react";
import { KeyHints, PHASE_META, cx, outcomeLabel, outcomeTone, toneClass } from "./shared.js";
import { PhasePrompt } from "./PhasePrompt.js";
import { PhaseRail } from "./PhaseRail.js";
import { PlanningCard } from "./PlanningCard.js";
import { TerminalFrame } from "./TerminalFrame.js";
import type { KeyHint, PhaseCockpitProps, Surface } from "./types.js";

function contextTone(context: string): "success" | "warn" | "muted" {
  const normalized = context.toLowerCase();
  if (normalized.includes("not built") || normalized.includes("missing")) return "muted";
  if (normalized.includes("stale") || normalized.includes("partial")) return "warn";
  return "success";
}

function CommandHints({ hints }: { hints?: readonly KeyHint[] }): React.ReactElement | null {
  if (!hints?.length) return null;
  return (
    <div className="kz-command-hints">
      {hints.map((hint) => <span key={`${hint.key}:${hint.label}`}>{hint.key} {hint.label}</span>)}
    </div>
  );
}

function resultGlyph(outcome: NonNullable<PhaseCockpitProps["result"]>["outcome"]): string {
  switch (outcome) {
    case "success": return "✓";
    case "partial":
    case "degraded":
    case "stale": return "⚠";
    case "failed": return "✗";
    case "canceled":
    case "interrupted": return "×";
  }
}

function SurfacePanel({ surface, focused }: { surface: Surface; focused: boolean }): React.ReactElement {
  return (
    <section className={cx("kz-surface", `kz-surface-${surface.state ?? "available"}`, focused && "kz-surface-focused")}>
      <div className="kz-pane-title">{focused && <span>▸ </span>}{surface.title.toUpperCase()}</div>
      <div className="kz-surface-lines">
        {surface.lines.map((line, index) => (
          <div className={cx("kz-surface-line", toneClass(line.tone), line.selected && "kz-selected")} key={`${surface.id}:${index}`}>
            {line.selected && <span>▸ </span>}{line.text}
          </div>
        ))}
      </div>
      {surface.footer && <div className="kz-surface-footer">{surface.footer}</div>}
    </section>
  );
}

function ResultCard({ result }: { result: NonNullable<PhaseCockpitProps["result"]> }): React.ReactElement {
  return (
    <section className={cx("kz-result-card", `kz-tone-${outcomeTone(result.outcome)}`)}>
      <div className="kz-result-title">{resultGlyph(result.outcome)} {result.title}</div>
      <div className="kz-result-detail">{result.detail}</div>
      <div className="kz-result-next">▸ NEXT {result.recommended}</div>
      <KeyHints hints={result.controls} />
    </section>
  );
}

export function PhaseCockpit({
  phase,
  reality,
  target,
  context = "context: ready",
  status = "idle",
  next,
  model,
  module,
  cost,
  rail,
  result,
  actions,
  surfaces,
  focusedSurface,
  plan,
  prompt,
  footer,
  cols = 80,
  rows = 24,
}: PhaseCockpitProps): React.ReactElement {
  const meta = PHASE_META[phase];
  const { hints: promptHints, ...phasePrompt } = prompt ?? {};
  const headerRows = cols >= 60 ? 4 : 3;
  const lowerRows = 1 + (footer ? 2 : 0) + (plan ? Math.min(7, plan.tasks.length + 3) : 0);
  const bodyRows = Math.max(0, rows - headerRows - lowerRows);
  const density = result
    ? "sparse"
    : cols >= 120 && bodyRows >= 16
    ? "dense"
    : cols >= 78 && bodyRows >= 10
      ? "master-detail"
      : "sparse";
  const visibleSurfaces = surfaces.slice(0, density === "dense" ? 3 : density === "master-detail" ? 2 : 1);
  const effectiveFocus = focusedSurface && visibleSurfaces.some((surface) => surface.id === focusedSurface)
    ? focusedSurface
    : visibleSurfaces[0]?.id;
  return (
    <TerminalFrame title={`kuzushi · ${meta.label.toLowerCase()}`} cols={cols} rows={rows} chromeless>
      <div className={cx("kz-screen", "kz-phase-cockpit", `kz-density-${density}`, `kz-phase-${phase}`)}>
        <header className="kz-engagement-header">
          <div className="kz-identity-line">
            <strong>KUZUSHI</strong>
            <span className="kz-separator">·</span>
            <span className="kz-mode-label">VIEW {meta.label}</span>
            {reality && reality !== phase && <><span className="kz-separator">·</span><span className="kz-secondary-meta">REALITY {PHASE_META[reality].label}</span></>}
            <span className="kz-separator">·</span>
            <span>target {target}</span>
            <span className="kz-separator">·</span>
            <span className={toneClass(outcomeTone(status))}>{outcomeLabel(status)}</span>
            {cost && <><span className="kz-separator">·</span><span>cost {cost}</span></>}
            <span className="kz-separator">·</span>
            <span className={toneClass(contextTone(context))}>{context}</span>
            {model && <><span className="kz-separator">·</span><span className="kz-secondary-meta">model {model}</span></>}
            {module && <><span className="kz-separator">·</span><span className="kz-secondary-meta">module {module}</span></>}
          </div>
          {cols >= 60 && <PhaseRail current={reality ?? phase} statuses={rail} />}
          <div className="kz-next-line"><strong>▸ NEXT </strong>{next}</div>
        </header>
        {result && <ResultCard result={result} />}
        {!result && cols >= 80 && <CommandHints hints={actions} />}
        <main className="kz-phase-surfaces">
          {visibleSurfaces.map((surface) => <SurfacePanel key={surface.id} surface={surface} focused={!result && surface.id === effectiveFocus} />)}
        </main>
        <div className="kz-bottom-workflow">
          {footer && rows >= 6 && (
            <div className="kz-footer-chrome">
              <div className="kz-status-footer">
                <span>{footer.left}</span>
                {footer.right && <span>{footer.right}</span>}
              </div>
              {rows >= 8 && <KeyHints hints={footer.controls ?? promptHints} />}
            </div>
          )}
          {plan && rows >= 6 && <PlanningCard {...plan} />}
          <PhasePrompt phase={phase} {...phasePrompt} hints={footer && rows >= 6 ? undefined : promptHints} />
        </div>
      </div>
    </TerminalFrame>
  );
}
