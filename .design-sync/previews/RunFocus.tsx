import { RunFocus } from "@kuzushi/tui-kit";

const plannerOutput = [
  { source: "planner", text: "asking model for a structured proposal", tone: "accent" },
  { source: "policy", text: "phase tools constrained by descriptor metadata", tone: "muted" },
  { source: "planner", text: "validating proposal against the active target", tone: "primary" },
] as const;

const plannerTasks = [
  { id: "intent", label: "Interpret operator intent", state: "done", detail: "phase scope retained" },
  { id: "catalog", label: "Resolve allowed tools", state: "done", detail: "descriptor-backed" },
  { id: "proposal", label: "Build structured proposal", state: "running", detail: "model active" },
] as const;

const planner = (phase: "map" | "scan" | "review" | "prove" | "fix", intent: string) => (
  <RunFocus
    phase={phase}
    runId={`plan-${phase}-01`}
    state="live"
    context={`target ./phase-target · planner intent: ${intent}`}
    health="current proposal · last progress now · run paused safely only for operator input"
    tasks={plannerTasks}
    output={plannerOutput}
    currentTask="proposal"
    cols={120}
    rows={36}
  />
);

export const A_MapPlannerRunning120x36 = () => planner("map", "refresh repository context before scanning");

export const B_ScanPlannerRunning120x36 = () => planner("scan", "scan the authenticated request boundary");

export const C_ReviewPlannerRunning120x36 = () => planner("review", "review critical and high-confidence candidates");

export const D_ProvePlannerRunning120x36 = () => planner("prove", "strengthen proof for F-0001 without changing code");

export const E_FixPlannerRunning120x36 = () => planner("fix", "fix the verified SQL injection");

export const F_LiveScan120x36 = () => (
  <RunFocus
    phase="scan"
    runId="scan-20260716-142233"
    state="live"
    context="target ./phase-target · sast:scan · revision ccb29fa"
    health="current semgrep · last progress 2s ago · heartbeat authoritative"
    tasks={[
      { id: "inventory", label: "Inventory target", state: "done", detail: "3 files" },
      { id: "semgrep", label: "Run Semgrep rules", state: "running", detail: "18/24 rules" },
      { id: "structural", label: "Resolve structural paths", state: "pending" },
      { id: "normalize", label: "Normalize findings", state: "pending" },
      { id: "persist", label: "Persist run receipt", state: "pending" },
    ]}
    output={[
      { source: "inventory", text: "indexed 3 files · Rust · Cargo workspace", tone: "success" },
      { source: "semgrep", text: "rule rust.sql.string-concat matched routes/login.rs:84", tone: "warn" },
      { source: "semgrep", text: "candidate F-0001 retained for normalization" },
      { source: "run", text: "trace appended · cost >=$0.018 incomplete", tone: "muted" },
    ]}
    currentTask="semgrep"
    cols={120}
    rows={36}
  />
);

export const G_CompletedRunFocus120x36 = () => (
  <RunFocus
    phase="prove"
    runId="verify-f0001"
    state="completed"
    context="target ./phase-target · verify:finding F-0001 · revision ccb29fa"
    health="terminal receipt durable · proof artifact proof.json · cost $0.031 complete"
    tasks={[
      { id: "replay", label: "Replay discovery evidence", state: "done" },
      { id: "exercise", label: "Exercise controlled payload", state: "done" },
      { id: "observe", label: "Record runtime effect", state: "done" },
      { id: "persist", label: "Persist proof artifact", state: "done" },
    ]}
    output={[
      { source: "verify", text: "payload changed response from 401 to 200", tone: "danger" },
      { source: "proof", text: "runtime_verified · level L4 · 1 source", tone: "success" },
      { source: "artifact", text: ".kuzushi/v3/runs/verify-f0001/proof.json", tone: "accent" },
    ]}
    cols={120}
    rows={36}
  />
);

export const H_PartialRunFocus80x24 = () => (
  <RunFocus
    phase="scan"
    runId="scan-partial-02"
    state="partial"
    context="target ./phase-target · sast:scan · accepted attempt pending acknowledgement"
    health="2 engines completed · CodeQL unavailable · durable lower-bound cost >=$0.041"
    tasks={[
      { id: "semgrep", label: "Semgrep", state: "done", detail: "4 candidates" },
      { id: "treesitter", label: "Tree-sitter", state: "done", detail: "3 paths" },
      { id: "codeql", label: "CodeQL", state: "failed", detail: "binary not found" },
      { id: "normalize", label: "Normalize available results", state: "done" },
    ]}
    output={[
      { source: "codeql", text: "binary not found; no fallback engine substituted", tone: "warn" },
      { source: "result", text: "partial · 4 candidates · acknowledgement required", tone: "warn" },
      { source: "artifact", text: "summary.json and trace.jsonl persisted", tone: "success" },
    ]}
    cols={80}
    rows={24}
  />
);

export const I_InterruptedRunFocus40x12 = () => (
  <RunFocus
    phase="fix"
    runId="patch-f0001"
    state="interrupted"
    context="target ./phase-target · patch apply"
    health="process loss after cancellation escalation · cleanup receipt persisted"
    tasks={[
      { id: "stage", label: "Stage patch", state: "done" },
      { id: "apply", label: "Apply patch", state: "failed" },
      { id: "reverify", label: "Reverify", state: "blocked" },
    ]}
    output={[
      { source: "run", text: "interrupted before application could be verified", tone: "warn" },
      { source: "next", text: "inspect trace, then retry from the staged patch", tone: "accent" },
    ]}
    focus="output"
    cols={40}
    rows={12}
  />
);
