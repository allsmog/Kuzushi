import { Fragment } from "react";
import { Glyph } from "./Glyph";
import { Row } from "./Row";
import type { Severity, Tone } from "./tokens";

export interface AttackStage {
  /** Stage label (e.g. `req.body.id`, `buildQuery`, `db.exec`). */
  label: string;
  /** Tone override; defaults by position (source high, hops medium, sink by severity). */
  tone?: Tone;
}

const SEV_TONE: Record<Severity, Tone> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
  unknown: "unknown",
};

function center(text: string, width: number): string {
  const clipped = text.length > width ? text.slice(0, width) : text;
  const pad = width - clipped.length;
  const left = Math.floor(pad / 2);
  return " ".repeat(left) + clipped + " ".repeat(pad - left);
}

export interface AttackPathProps {
  /** The ordered taint stages: source first, sink last. */
  stages: AttackStage[];
  /** CWE label for the header/footer (e.g. `CWE-89`). */
  cwe?: string;
  /** Overall flow severity — tones the sink box and the footer. */
  severity?: Severity;
  /** Inner width of each stage box, in cells. */
  boxWidth?: number;
}

/**
 * The taint-flow attack path — horizontal `╭─╮ │ ╰─╯` stage boxes joined by
 * `─▶` arrows, from source to sink, mirroring the Rust scene attack-path
 * diagram. The source box reads high, the sink takes the flow's overall
 * severity, and the hops between read medium, so the eye follows tainted data
 * from where it enters to where it lands. A header names the CWE and severity;
 * a footer summarises the stage count.
 *
 * @example
 * <AttackPath cwe="CWE-89" severity="critical" stages={[
 *   { label: "req.body.id" },
 *   { label: "buildQuery" },
 *   { label: "db.exec" },
 * ]} />
 */
export function AttackPath({ stages, cwe = "CWE-89", severity = "high", boxWidth = 12 }: AttackPathProps) {
  const sevTone = SEV_TONE[severity];
  const toneFor = (i: number): Tone => {
    if (stages[i].tone) return stages[i].tone as Tone;
    if (i === 0) return "high";
    if (i === stages.length - 1) return sevTone;
    return "medium";
  };
  const arrow = " ─▶ ";
  return (
    <>
      <Row>
        {" "}
        <Glyph tone="label">taint flow</Glyph>
        {"  "}
        <Glyph tone="muted">{cwe}</Glyph>
        <Glyph tone="subtle"> · </Glyph>
        <Glyph tone={sevTone}>{severity.toUpperCase()}</Glyph>
      </Row>
      <Row> </Row>
      <Row>
        {" "}
        {stages.map((_, i) => (
          <Fragment key={i}>
            <Glyph tone={toneFor(i)}>{`╭${"─".repeat(boxWidth)}╮`}</Glyph>
            {i !== stages.length - 1 ? <Glyph tone="subtle">{"    "}</Glyph> : null}
          </Fragment>
        ))}
      </Row>
      <Row>
        {" "}
        {stages.map((s, i) => (
          <Fragment key={i}>
            <Glyph tone={toneFor(i)}>{`│${center(s.label, boxWidth)}│`}</Glyph>
            {i !== stages.length - 1 ? <Glyph tone="subtle">{arrow}</Glyph> : null}
          </Fragment>
        ))}
      </Row>
      <Row>
        {" "}
        {stages.map((_, i) => (
          <Fragment key={i}>
            <Glyph tone={toneFor(i)}>{`╰${"─".repeat(boxWidth)}╯`}</Glyph>
            {i !== stages.length - 1 ? <Glyph tone="subtle">{"    "}</Glyph> : null}
          </Fragment>
        ))}
      </Row>
      <Row> </Row>
      <Row>
        {" "}
        <Glyph tone="muted">{cwe}</Glyph>
        <Glyph tone="subtle"> · </Glyph>
        <Glyph tone={sevTone}>{severity.toUpperCase()}</Glyph>
        <Glyph tone="muted">{` · ${stages.length}-stage source → sink flow`}</Glyph>
      </Row>
    </>
  );
}
