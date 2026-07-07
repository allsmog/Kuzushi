import type { ReactNode } from "react";
import { Glyph } from "./Glyph";
import { Row } from "./Row";
import { type LogKind, LOG_GLYPH } from "./tokens";

export interface LogLineProps {
  /**
   * The line kind, which selects the leading glyph and its tone:
   * `in ●` operator input · `run ⏵` dispatch · `ok ✓` · `err ✗` ·
   * `agent ◆` · `flow …` · `find ▸` · `log ·`.
   */
  kind?: LogKind;
  /** Timestamp prefix (e.g. `14:31:55`), rendered subtle. */
  time?: string;
  /** Fix the line to a grid width in cells. */
  cols?: number;
  /** The line body — plain text and {@link Glyph} spans. */
  children: ReactNode;
}

/**
 * A console line: a subtle timestamp, a kind glyph, and the message body.
 * These stack to form the growing transcript that is the heart of the Kuzushi
 * shell — every dispatch, agent message, and finding is one `LogLine`.
 *
 * @example
 * <LogLine kind="run" time="14:31:55"> sast:scan · tasks <Glyph tone="accent">semgrep, secrets</Glyph></LogLine>
 * <LogLine kind="find" time="14:33:42"> <Glyph tone="primary">F-0012</Glyph> · <SeverityBadge level="critical" /></LogLine>
 */
export function LogLine({ kind = "log", time, cols, children }: LogLineProps) {
  const { glyph, tone } = LOG_GLYPH[kind];
  return (
    <Row cols={cols}>
      {" "}
      {time != null && (
        <>
          <Glyph tone="subtle">{time}</Glyph>{" "}
        </>
      )}
      <Glyph tone={tone}>{` ${glyph} `}</Glyph>
      {children}
    </Row>
  );
}
