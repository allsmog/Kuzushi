import { Glyph } from "./Glyph";
import { Row } from "./Row";
import { SectionHeader } from "./SectionHeader";
import type { Severity, Tone } from "./tokens";

/** Per-module finding counts, one entry per severity column. */
export interface HeatmapModule {
  /** Module / area name (e.g. `payments`, `auth`). */
  name: string;
  /** Finding count per severity — omitted levels read as zero. */
  counts: Partial<Record<Severity, number>>;
}

const COLUMNS: { level: Severity; head: string }[] = [
  { level: "critical", head: "C" },
  { level: "high", head: "H" },
  { level: "medium", head: "M" },
  { level: "low", head: "L" },
  { level: "info", head: "I" },
];

const SEV_TONE: Record<Severity, Tone> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
  unknown: "unknown",
};

function cap(count: number): string {
  return count > 999 ? "999+" : String(count);
}

export interface HeatmapProps {
  /** Section title (default `FINDINGS HEATMAP`). */
  title?: string;
  /** One row per module; columns are the five severity levels. */
  modules: HeatmapModule[];
  /** Max `█` cells a bar can grow to (the busiest cell). */
  barMax?: number;
  /** Fix rows to a grid width in cells. */
  cols?: number;
}

/**
 * The findings heatmap — a module × severity grid where each cell is a `█`-block
 * bar whose width tracks the finding count and whose colour is the severity
 * column, mirroring the Rust scene heatmap. It answers "where is the risk
 * concentrated?" at a glance: the longest, reddest bars are the modules to hunt
 * first. Empty cells read as a subtle `·`.
 *
 * @example
 * <Heatmap cols={64} modules={[
 *   { name: "payments", counts: { critical: 2, high: 3, medium: 1 } },
 *   { name: "auth",     counts: { high: 1, low: 4 } },
 *   { name: "reports",  counts: { info: 6 } },
 * ]} />
 */
export function Heatmap({ title = "FINDINGS HEATMAP", modules, barMax = 8, cols }: HeatmapProps) {
  const nameWidth = Math.max(8, ...modules.map((m) => m.name.length));
  const peak = Math.max(1, ...modules.flatMap((m) => COLUMNS.map((c) => m.counts[c.level] ?? 0)));
  const scale = (n: number) => Math.min(barMax, Math.round((n / peak) * barMax));
  return (
    <>
      <SectionHeader label={title} cols={cols} />
      <Row cols={cols}>
        {" "}
        <Glyph tone="muted">{"module".padEnd(nameWidth)}</Glyph>
        {"  "}
        {COLUMNS.map((c) => (
          <Glyph key={c.level} tone={SEV_TONE[c.level]}>{`${c.head}       `}</Glyph>
        ))}
      </Row>
      {modules.map((m) => (
        <Row key={m.name} cols={cols}>
          {" "}
          <Glyph tone="primary">{m.name.padEnd(nameWidth)}</Glyph>
          {"  "}
          {COLUMNS.map((c) => {
            const n = m.counts[c.level] ?? 0;
            if (n === 0) return <Glyph key={c.level} tone="subtle">{"·       "}</Glyph>;
            const bar = "█".repeat(Math.max(1, scale(n)));
            const readout = ` ${cap(n)}`;
            const cell = `${bar}${readout}`.padEnd(8).slice(0, 8);
            return <Glyph key={c.level} tone={SEV_TONE[c.level]}>{cell}</Glyph>;
          })}
        </Row>
      ))}
      <Row cols={cols}>
        {" "}
        <Glyph tone="subtle">bar width ∝ count · colour = severity column · · = none</Glyph>
      </Row>
    </>
  );
}
