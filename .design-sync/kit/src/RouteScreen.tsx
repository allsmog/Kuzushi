import * as React from "react";
import { KeyHints, SectionRule, cx, toneClass } from "./shared.js";
import { TerminalFrame } from "./TerminalFrame.js";
import type { RouteScreenProps } from "./types.js";

export function RouteScreen({
  route,
  title,
  context,
  rows,
  selected,
  footer,
  cols = 80,
  height = 24,
}: RouteScreenProps): React.ReactElement {
  return (
    <TerminalFrame title={`kuzushi · ${route}`} cols={cols} rows={height} chromeless>
      <div className="kz-screen kz-route-screen">
        <header>
          <SectionRule label={title.toUpperCase()} />
          {context && <div className="kz-context-line">{context}</div>}
        </header>
        <main className="kz-route-rows">
          {rows.map((row, index) => (
            <div className={cx("kz-route-row", toneClass(row.tone), index === selected && "kz-selected")} key={row.id}>
              {selected !== undefined && <span className="kz-route-marker">{index === selected ? "▸" : " "}</span>}
              {row.cells?.length ? (
                row.cells.map((cell, cellIndex) => <span key={`${row.id}:${cellIndex}`}>{cell}</span>)
              ) : row.text}
              {row.detail && <small>{row.detail}</small>}
            </div>
          ))}
        </main>
        <footer className="kz-route-footer"><KeyHints hints={footer} /></footer>
      </div>
    </TerminalFrame>
  );
}
