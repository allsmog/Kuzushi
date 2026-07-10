import { TermFrame, NextCallout } from "@kuzushi/tui-kit";

// The confirm-phase callout — findings are landing and need operator review. The
// primary use: the ▸ NEXT line anchoring the top bar, pointing at the real next step.
export function ConfirmPhase() {
  return (
    <TermFrame chromeless cols={72}>
      <NextCallout cols={72} summary="作 confirm · 3 findings need review — next to continue" />
    </TermFrame>
  );
}

// The hunt-phase callout — modules still unscanned, so the next move is more coverage.
export function HuntPhase() {
  return (
    <TermFrame chromeless cols={72}>
      <NextCallout cols={72} summary="崩 hunt · 2 modules unscanned — next to continue the sweep" />
    </TermFrame>
  );
}

// The phase axis swept — the same callout across the map → hunt → fix journey, so the
// summary always reflects workspace reality rather than a generic prompt.
export function AcrossPhases() {
  return (
    <TermFrame chromeless cols={72}>
      <NextCallout cols={72} summary="組 map · no threat model yet — next to build the DFD" />
      <NextCallout cols={72} summary="崩 hunt · taint-iris ready — next to hunt refund-bot.ts" />
      <NextCallout cols={72} summary="掛 fix · 1 confirmed finding — next to draft the patch" />
    </TermFrame>
  );
}
