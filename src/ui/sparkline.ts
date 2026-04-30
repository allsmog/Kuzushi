/**
 * severitySparkline — five-glyph severity profile for catalog `LAST RUN`.
 *
 * Renders left-to-right as `critical · high · medium · low · info`. Each
 * bucket maps its count onto a 9-step block ramp so a single glance reads
 * the relative weight of each severity tier. Zero-count buckets render as
 * a muted `·` so the column stays a fixed five visible characters wide,
 * which keeps the catalog table math predictable.
 *
 * Output is an ANSI-coded string (no JSX) so it composes cleanly through
 * the `Table` primitive's string-only render path. Color tokens already
 * respect `NO_COLOR` and `KUZUSHI_HIGH_CONTRAST=1`, so accessibility
 * inheritance is automatic.
 */
import { tokens } from "./tokens.js";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"] as const;

function bucket(n: number): string {
  if (n <= 0) return "·";
  if (n === 1) return "▁";
  if (n === 2) return "▂";
  if (n <= 4) return "▃";
  if (n <= 7) return "▄";
  if (n <= 15) return "▅";
  if (n <= 31) return "▆";
  if (n <= 63) return "▇";
  return "█";
}

const COLOR: Record<(typeof SEV_ORDER)[number], (text: string) => string> = {
  critical: tokens.dangerStrong,
  high: tokens.danger,
  medium: tokens.warn,
  low: tokens.info,
  info: tokens.muted,
};

export function severitySparkline(counts?: Record<string, number>): string {
  if (!counts) return "";
  let any = false;
  const segments = SEV_ORDER.map((sev) => {
    const n = counts[sev] ?? 0;
    if (n > 0) any = true;
    const glyph = bucket(n);
    if (n <= 0) return tokens.muted(glyph);
    return COLOR[sev](glyph);
  });
  return any ? segments.join("") : "";
}
