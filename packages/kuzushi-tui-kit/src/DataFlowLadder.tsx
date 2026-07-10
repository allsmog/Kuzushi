import { Fragment } from "react";
import { Glyph } from "./Glyph";
import { Row } from "./Row";
import { SectionHeader } from "./SectionHeader";
import type { Tone } from "./tokens";

/** A leg's role in the taint ladder. */
export type LegKind = "source" | "hop" | "sink";

export interface FlowLeg {
  /** Leg label (e.g. `req.body.id`, `sanitize()`, `db.exec`). */
  label: string;
  /** source ● · hop ○ · sink ◆ — sets the glyph and tone. */
  kind: LegKind;
  /** Optional trailing note (e.g. a file:line or transform name). */
  note?: string;
  /** Whether the taint actually reaches this waypoint (`✓`) or not yet (`○`). */
  reached?: boolean;
}

const LEG: Record<LegKind, { glyph: string; tone: Tone }> = {
  source: { glyph: "●", tone: "accent" },
  hop: { glyph: "○", tone: "muted" },
  sink: { glyph: "◆", tone: "danger" },
};

const CIRCLED = ["①", "②", "③", "④", "⑤", "⑥", "⑦", "⑧", "⑨", "⑩"];
function circled(i: number): string {
  return i < CIRCLED.length ? CIRCLED[i] : `(${i + 1})`;
}

export interface DataFlowLadderProps {
  /** Section title (default `DATA-FLOW`). */
  title?: string;
  /** The ordered legs, source first, sink last. */
  legs: FlowLeg[];
}

/**
 * The taint data-flow ladder — the depth-stack review drill's centre pane. Each
 * leg is a circled index (`①②③`) plus its role glyph (`●` source / `○` hop /
 * `◆` sink) and a reached marker (`✓`/`○`); the heavy `═══▶` connector marks the
 * source leg and light `──▶` connectors mark the hops, mirroring the Rust
 * data-flow ladder. Read top-to-bottom, it traces tainted data from where it
 * enters to the sink it reaches.
 *
 * @example
 * <DataFlowLadder title="CWE-89" legs={[
 *   { kind: "source", label: "req.body.id", note: "handler.ts:20", reached: true },
 *   { kind: "hop", label: "buildQuery", note: "sql.ts:44", reached: true },
 *   { kind: "sink", label: "db.exec", note: "db.ts:9", reached: true },
 * ]} />
 */
export function DataFlowLadder({ title = "DATA-FLOW", legs }: DataFlowLadderProps) {
  return (
    <>
      <SectionHeader label={title} />
      {legs.map((leg, i) => {
        const l = LEG[leg.kind];
        return (
          <Fragment key={i}>
            <Row>
              {" "}
              <Glyph tone="subtle">{circled(i)}</Glyph>{" "}
              <Glyph tone={l.tone}>{l.glyph}</Glyph>{" "}
              <Glyph tone={leg.kind === "sink" ? "danger" : "primary"}>{leg.label}</Glyph>
              {leg.note ? <Glyph tone="muted">{`  ${leg.note}`}</Glyph> : null}
              {leg.reached != null ? (
                <Glyph tone={leg.reached ? "success" : "subtle"}>{`  ${leg.reached ? "✓" : "○"}`}</Glyph>
              ) : null}
            </Row>
            {i !== legs.length - 1 ? (
              <Row>
                {"   "}
                <Glyph tone={leg.kind === "source" ? "accent" : "subtle"}>
                  {leg.kind === "source" ? "═══▶" : "──▶"}
                </Glyph>
              </Row>
            ) : null}
          </Fragment>
        );
      })}
    </>
  );
}
