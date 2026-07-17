import { PlanningCard, TerminalFrame } from "@kuzushi/tui-kit";

export const A_ReturnedMapProposal = () => (
  <TerminalFrame title="returned plan · map" cols={80} rows={14}>
    <PlanningCard
      returned
      state="completed"
      goal="refresh the repository map before scanning"
      summary="Rebuild deterministic context, then update trust boundaries."
      tasks={[
        { id: "context", label: "context:build — refresh target inventory", selected: true },
        { id: "threat", label: "threat-model:build — update trust boundaries" },
      ]}
    />
  </TerminalFrame>
);

export const B_ReturnedProveProposal = () => (
  <TerminalFrame title="returned plan · prove" cols={80} rows={15}>
    <PlanningCard
      returned
      state="partial"
      goal="strengthen proof for F-0001 without changing code"
      summary="Replay the recorded run, then verify the displayed finding."
      tasks={[
        { id: "replay", label: "replay scan-phase-run — inspect durable evidence", selected: true },
        { id: "verify", label: "verify:finding F-0001 — collect runtime proof" },
        { id: "patch", label: "patch:finding F-0001 — out of Prove scope", skipped: true, state: "blocked" },
      ]}
    />
  </TerminalFrame>
);

export const C_ToggledFixProposal = () => (
  <TerminalFrame title="returned plan · fix" cols={80} rows={15}>
    <PlanningCard
      returned
      state="completed"
      goal="fix the verified SQL injection"
      summary="Draft one parameterized-query patch and reverify after approval."
      tasks={[
        { id: "draft", label: "patch:finding F-0001 — draft reviewed diff", selected: true },
        { id: "apply", label: "patch apply — requires operator approval", skipped: true },
        { id: "verify", label: "verify:finding F-0001 — reverify applied patch" },
      ]}
    />
  </TerminalFrame>
);
