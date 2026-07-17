import * as React from "react";
import { SectionRule, cx } from "./shared.js";
import { TerminalFrame } from "./TerminalFrame.js";
import type { SetupScreenProps, SetupTone } from "./types.js";

const GLYPH: Record<SetupTone, string> = {
  ready: "✓",
  optional: "·",
  blocked: "!",
  action: " ",
};

export function SetupScreen({
  target,
  readiness,
  facts,
  action,
  cols = 80,
  rows = 24,
}: SetupScreenProps): React.ReactElement {
  const canStart = action?.ready ?? !readiness.some((row) => row.tone === "blocked");
  const compact = cols < 72;
  return (
    <TerminalFrame title="kuzushi · setup" cols={cols} rows={rows} chromeless>
      <div className="kz-screen kz-setup-screen">
        <header>
          <SectionRule label="SETUP · READY THE MAP RUN" />
          <div className="kz-muted">One readiness check. Model and credentials are required only by the selected plan.</div>
          <div className="kz-context-line">target:{target}</div>
        </header>
        <main className="kz-setup-body">
          <section className="kz-readiness-list">
            {readiness.map((row) => (
              <React.Fragment key={row.id}>
                <div className={cx("kz-setup-row", compact && "kz-setup-row-compact", `kz-setup-${row.tone}`, row.selected && "kz-selected")}>
                  {compact ? (
                    <span>{GLYPH[row.tone]} {row.label} {row.status} · {row.detail}</span>
                  ) : (
                    <>
                      <span>{GLYPH[row.tone]}</span>
                      <span className="kz-setup-label">{row.label}</span>
                      <strong>{row.status}</strong>
                    </>
                  )}
                </div>
                {!compact && row.selected && <div className="kz-setup-selected-detail">    {row.detail}</div>}
              </React.Fragment>
            ))}
          </section>
          {facts?.length ? (
            <section className="kz-setup-facts">
              <SectionRule label="TARGET FACTS" />
              {facts.map((fact) => <div key={fact.label}><span>{fact.label}</span> <strong>{fact.value}</strong></div>)}
            </section>
          ) : null}
        </main>
        <footer className={cx("kz-setup-summary", canStart ? "kz-tone-success" : "kz-tone-warn")}>
          {canStart
            ? `READY · ${action?.selectedTasks ?? 0} Map task(s) · Enter ${action?.label ?? "Start Map"} to commit`
            : "BLOCKED · resolve the first highlighted readiness row"}
        </footer>
      </div>
    </TerminalFrame>
  );
}
