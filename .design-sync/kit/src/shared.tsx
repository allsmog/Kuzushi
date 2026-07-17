import * as React from "react";
import type { CSSProperties, ReactNode } from "react";
import type { KeyHint, Outcome, Phase, Tone } from "./types.js";

export const PHASE_META: Record<Phase, { token: string; kanji: string; label: string; placeholder: string }> = {
  map: { token: "◇", kanji: "組", label: "MAP", placeholder: "describe what to map" },
  scan: { token: "▦", kanji: "崩", label: "SCAN", placeholder: "describe what to scan" },
  review: { token: "▣", kanji: "覧", label: "REVIEW", placeholder: "describe what to review" },
  prove: { token: "◎", kanji: "証", label: "PROVE", placeholder: "describe what to verify" },
  fix: { token: "◆", kanji: "掛", label: "FIX", placeholder: "describe the patch to draft" },
};

export function cx(...classes: readonly (string | false | null | undefined)[]): string {
  return classes.filter(Boolean).join(" ");
}

export function terminalStyle(cols: number, rows: number): CSSProperties {
  return {
    "--kz-cols": cols,
    "--kz-rows": rows,
  } as CSSProperties;
}

export function toneClass(tone: Tone | undefined): string | undefined {
  return tone ? `kz-tone-${tone}` : undefined;
}

export function outcomeTone(outcome: Outcome): Tone {
  switch (outcome) {
    case "success":
      return "success";
    case "partial":
    case "degraded":
    case "stale":
    case "interrupted":
      return "warn";
    case "failed":
      return "danger";
    case "running":
      return "success";
    default:
      return "muted";
  }
}

export function outcomeLabel(outcome: Outcome): string {
  switch (outcome) {
    case "loading": return "◌ LOADING";
    case "running": return "● LIVE";
    case "success": return "✓ COMPLETE";
    case "partial": return "⚠ PARTIAL";
    case "failed": return "✗ FAILED";
    case "canceled": return "× CANCELED";
    case "interrupted": return "× INTERRUPTED";
    case "degraded": return "⚠ DEGRADED";
    case "stale": return "⚠ STALE";
    default: return "○ idle";
  }
}

export function KeyHints({ hints }: { hints?: readonly KeyHint[] }): React.ReactElement | null {
  if (!hints?.length) return null;
  return (
    <div className="kz-key-hints">
      {hints.map((hint) => (
        <span className="kz-key-hint" key={`${hint.key}:${hint.label}`}>
          <b>{hint.key}</b> {hint.label}
        </span>
      ))}
    </div>
  );
}

export function SectionRule({ label, tone }: { label: string; tone?: Tone }): React.ReactElement {
  return (
    <div className={cx("kz-section-rule", toneClass(tone))}>
      <span>── </span>
      <strong>{label}</strong>
      <span className="kz-rule-fill" aria-hidden="true" />
    </div>
  );
}

export function FitLine({ children, className }: { children: ReactNode; className?: string }): React.ReactElement {
  return <div className={cx("kz-fit-line", className)}>{children}</div>;
}
