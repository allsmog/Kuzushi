import { TermFrame, SectionHeader, ProposalRow } from "@kuzushi/tui-kit";

// The hunt queue mid-triage — the full disposition axis in one stack: a kept
// proposal, the running dispatch (the j/k cursor line), a fresh proposed row
// awaiting a keep/skip, a skipped candidate, and a failed one.
export function HuntQueue() {
  return (
    <TermFrame chromeless cols={88}>
      <SectionHeader label="HUNT QUEUE · 5 proposed · budget $2.00" cols={88} />
      <ProposalRow
        id="P-001"
        title="incomplete-fix hunt"
        generator="commits"
        price="$0.40"
        yieldScore={0.82}
        state="kept"
        cols={88}
      />
      <ProposalRow
        id="P-002"
        title="auth bypass in session refresh"
        generator="threat-model"
        price="$0.65"
        yieldScore={0.74}
        state="running"
        selected
        cols={88}
      />
      <ProposalRow
        id="P-003"
        title="ssrf via webhook url"
        generator="dep-intel"
        price="$0.35"
        yieldScore={0.61}
        state="proposed"
        cols={88}
      />
      <ProposalRow
        id="P-004"
        title="verbose stack trace leak"
        generator="commits"
        price="$0.20"
        yieldScore={0.31}
        state="skipped"
        cols={88}
      />
      <ProposalRow
        id="P-005"
        title="deserialization gadget sweep"
        generator="threat-model"
        price="$0.90"
        yieldScore={0.58}
        state="failed"
        cols={88}
      />
    </TermFrame>
  );
}
