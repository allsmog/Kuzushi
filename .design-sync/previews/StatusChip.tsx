import { TermFrame, StatusChip, Glyph } from "@kuzushi/tui-kit";

// The healthy cockpit strip — a live run, fresh context, scope gate on. The primary
// story: several chips separated by the ` · ` the status strip uses between fields.
export function HealthyStrip() {
  return (
    <TermFrame chromeless cols={64}>
      <Glyph tone="subtle">{" "}</Glyph>
      <StatusChip glyph="●" label="LIVE" tone="success" />
      <Glyph tone="subtle">{" · "}</Glyph>
      <StatusChip glyph="✓" label="ctx: built" tone="success" />
      <Glyph tone="subtle">{" · "}</Glyph>
      <StatusChip label="scope: on" tone="success" />
    </TermFrame>
  );
}

// The idle / not-yet-ready strip — nothing running, context not built, and a malformed
// context warning. The alternate states of the same three chips.
export function IdleStrip() {
  return (
    <TermFrame chromeless cols={64}>
      <Glyph tone="subtle">{" "}</Glyph>
      <StatusChip glyph="○" label="idle" tone="subtle" />
      <Glyph tone="subtle">{" · "}</Glyph>
      <StatusChip label="ctx: not built" tone="muted" />
      <Glyph tone="subtle">{" · "}</Glyph>
      <StatusChip glyph="⚠" label="ctx: malformed" tone="warn" />
    </TermFrame>
  );
}

// Single chips across the tone vocabulary — liveness, freshness, and the scope gate
// each in their semantic color, the atomic building block on its own.
export function ToneSweep() {
  return (
    <TermFrame chromeless cols={40}>
      <div><StatusChip glyph="●" label="LIVE" tone="success" /></div>
      <div><StatusChip glyph="○" label="idle" tone="subtle" /></div>
      <div><StatusChip glyph="✓" label="ctx: built" tone="success" /></div>
      <div><StatusChip glyph="⚠" label="ctx: malformed" tone="warn" /></div>
      <div><StatusChip label="scope: on" tone="success" /></div>
    </TermFrame>
  );
}
