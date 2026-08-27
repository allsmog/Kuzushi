import { RouteScreen } from "@kuzushi/tui-kit";

const closeFooter = [
  { key: "j/k", label: "move" },
  { key: "Enter", label: "open" },
  { key: "Esc", label: "return" },
] as const;

export const A_TargetSelection120x36 = () => (
  <RouteScreen
    route="target"
    title="CHOOSE TARGET"
    context="cwd is never assumed · Enter activates selection · Esc browses capabilities without a target"
    rows={[
      { id: "kuzushi", cells: ["Kuzushi", "git · ccb29fa · clean"], detail: "/workspace/Kuzushi" },
      { id: "recent", cells: ["phase-target", "git · 19ac321 · dirty"], detail: "/tmp/phase-target" },
      { id: "browse", cells: ["Choose another folder", "picker"], detail: "explicit selection required" },
    ]}
    selected={0}
    footer={closeFooter}
    cols={120}
    height={36}
  />
);

export const B_Report120x36 = () => (
  <RouteScreen
    route="report"
    title="REPORT · PREVIEW"
    context="target ./phase-target · revision ccb29fa · 6 findings · export has not written a file"
    rows={[
      { id: "format", cells: ["Format", "SARIF"], detail: "machine-readable security report" },
      { id: "scope", cells: ["Scope", "all findings"], detail: "1 critical · 2 high · 2 medium · 1 low" },
      { id: "proof", cells: ["Proof", "1 runtime verified"], detail: "2 unverified · 3 not applicable" },
      { id: "fix", cells: ["Fix", "1 staged"], detail: "0 applied · 0 reverified" },
      { id: "cost", cells: ["Cost", "$0.37 complete"], detail: "7 durable runs" },
      { id: "destination", cells: ["Destination", "./kuzushi-report.sarif"], detail: "preview only" },
    ]}
    selected={5}
    footer={[
      { key: "f", label: "format" },
      { key: "e", label: "edit path" },
      { key: "Enter", label: "export" },
      { key: "Esc", label: "return" },
    ]}
    cols={120}
    height={36}
  />
);

export const C_Jobs120x36 = () => (
  <RouteScreen
    route="jobs"
    title="JOBS"
    context="one authoritative live Run · queued work is pending · disk-only running rows are stale"
    rows={[
      { id: "live", cells: ["● LIVE", "scan-20260716-142233", "sast:scan", "42s"], detail: "current semgrep · 2/5 done" },
      { id: "queued", cells: ["· PENDING", "queue-03", "verify:finding F-0001", "—"], detail: "steer queue · waits for active plan" },
      { id: "complete", cells: ["✓ COMPLETE", "map-20260716-141901", "context:build", "8s"], detail: "$0.00 · summary.json" },
      { id: "partial", cells: ["⚠ PARTIAL", "scan-20260715-091202", "sast:scan", "31s"], detail: "CodeQL unavailable · acknowledged" },
      { id: "stale", cells: ["? running?", "scan-orphan-01", "sast:scan", "2d"], detail: "disk row has no live process authority" },
    ]}
    selected={0}
    footer={[
      { key: "Enter", label: "focus" },
      { key: "k", label: "cancel selected" },
      { key: "t", label: "trace" },
      { key: "Esc", label: "return" },
    ]}
    cols={120}
    height={36}
  />
);

export const D_Replay80x24 = () => (
  <RouteScreen
    route="replay"
    title="REPLAY · verify-f0001"
    context="read-only · durable artifact .kuzushi/v3/runs/verify-f0001 · revision ccb29fa"
    rows={[
      { id: "start", cells: ["00:00.000", "run.started"], detail: "verify:finding F-0001" },
      { id: "tool", cells: ["00:01.204", "tool.started"], detail: "runtime verifier" },
      { id: "input", cells: ["00:03.118", "evidence.observed"], detail: "controlled payload reached query predicate" },
      { id: "effect", cells: ["00:03.421", "proof.recorded"], detail: "response 401 → 200 · L4" },
      { id: "end", cells: ["00:03.690", "run.completed"], detail: "proof.json persisted · cost $0.031" },
    ]}
    footer={[
      { key: "j/k", label: "scroll" },
      { key: "t", label: "trace" },
      { key: "Esc", label: "return" },
    ]}
    cols={80}
    height={24}
  />
);

export const E_Trace120x36 = () => (
  <RouteScreen
    route="trace"
    title="TRACE · scan-20260716-142233"
    context="source-backed event stream · 128 rows · exact JSON available with Enter"
    rows={[
      { id: "1", cells: ["1", "run", "start"], detail: "module sast:scan · target digest 3a9b…" },
      { id: "2", cells: ["2", "inventory", "complete"], detail: "3 files · Rust" },
      { id: "3", cells: ["3", "semgrep", "progress"], detail: "18/24 rules" },
      { id: "4", cells: ["4", "finding", "candidate"], detail: "F-0001 · routes/login.rs:84" },
      { id: "5", cells: ["5", "cost", "lower-bound"], detail: ">=$0.018 incomplete" },
      { id: "6", cells: ["6", "artifact", "append"], detail: "trace.jsonl" },
    ]}
    selected={3}
    footer={[
      { key: "j/k", label: "scroll" },
      { key: "Enter", label: "inspect JSON" },
      { key: "/", label: "filter" },
      { key: "Esc", label: "return" },
    ]}
    cols={120}
    height={36}
  />
);

export const F_Catalog120x36 = () => (
  <RouteScreen
    route="catalog"
    title="CAPABILITY CATALOG"
    context="descriptor-backed inventory · target ./phase-target · headless truth retained"
    rows={[
      { id: "context", cells: ["context:build", "Map", "runtime-free"], detail: "Build target context artifacts" },
      { id: "sast", cells: ["  sast:scan", "Scan", "runtime optional"], detail: "Run the shared scan engine plan" },
      { id: "verify", cells: ["  verify:finding", "Prove", "runtime required"], detail: "Verify one durable finding" },
      { id: "patch", cells: ["  patch:finding", "Fix", "approval required"], detail: "Draft or apply a candidate patch" },
      { id: "report", cells: ["  report:export", "Report", "headless"], detail: "Export persisted findings and proof" },
    ]}
    selected={0}
    footer={[
      { key: "/", label: "filter" },
      { key: "Enter", label: "module" },
      { key: "o", label: "options" },
      { key: "Esc", label: "return" },
    ]}
    cols={120}
    height={36}
  />
);

export const G_Options80x24 = () => (
  <RouteScreen
    route="options"
    title="OPTIONS · sast:scan"
    context="OptionSpec is canonical · aliases are compatibility only · unknown keys are rejected"
    rows={[
      { id: "scope", cells: ["scope", "path", "./phase-target"], detail: "active target scope" },
      { id: "engines", cells: ["  engines", "list", "semgrep,tree-sitter"], detail: "selected scanner engines" },
      { id: "timeout", cells: ["  timeout", "duration", "15m"], detail: "shared scan/shell/run input" },
      { id: "model", cells: ["  model", "model-id", "operator config"], detail: "no silent fallback" },
    ]}
    selected={0}
    footer={closeFooter}
    cols={80}
    height={24}
  />
);

export const H_Help80x24 = () => (
  <RouteScreen
    route="help"
    title="HELP · REVIEW"
    context="contextual overlay · Esc restores Review and its input mode"
    rows={[
      { id: "move", cells: ["j/k", "move selection"] },
      { id: "open", cells: ["Enter", "inspect selected finding"] },
      { id: "accept", cells: ["a / r", "accept or reject candidate"] },
      { id: "filter", cells: ["f", "filter review queue"] },
      { id: "mode", cells: ["F2", "toggle Prompt / Navigate mode"] },
      { id: "palette", cells: ["Ctrl+G", "open command palette"] },
      { id: "close", cells: ["Esc", "return to exact origin"] },
    ]}
    footer={[
      { key: "/", label: "search help" },
      { key: "Esc", label: "close" },
    ]}
    cols={80}
    height={24}
  />
);

export const I_CommandPalette80x24 = () => (
  <RouteScreen
    route="palette"
    title="COMMAND PALETTE"
    context="query: run · origin Review · Prompt mode restored on close"
    rows={[
      { id: "run", cells: ["run <tool>", "execute a descriptor-backed tool"] },
      { id: "jobs", cells: ["  jobs", "inspect live and durable runs"] },
      { id: "replay", cells: ["  replay <runId>", "replay durable run events"] },
      { id: "trace", cells: ["  trace <runId>", "inspect source event stream"] },
      { id: "report", cells: ["  report", "open the report exit"] },
    ]}
    selected={0}
    footer={[
      { key: "type", label: "filter" },
      { key: "Enter", label: "load" },
      { key: "Esc", label: "close" },
    ]}
    cols={80}
    height={24}
  />
);

export const J_HealthAndAuth120x36 = () => (
  <RouteScreen
    route="health"
    title="HEALTH"
    context="operator diagnostics · no provider calls are made by this view"
    rows={[
      { id: "workspace", cells: ["✓ workspace", "ready"], detail: "target ./phase-target" },
      { id: "artifacts", cells: ["✓ artifacts", "readable"], detail: ".kuzushi/v3" },
      { id: "model", cells: ["! model", "configured"], detail: "openai:gpt-5.4 · authentication missing" },
      { id: "semgrep", cells: ["✓ semgrep", "available"], detail: "/opt/homebrew/bin/semgrep" },
      { id: "codeql", cells: ["! codeql", "missing"], detail: "partial scan coverage if selected" },
      { id: "joern", cells: ["· joern", "not required"], detail: "lazy server not started" },
    ]}
    selected={2}
    footer={[
      { key: "a", label: "open Auth" },
      { key: "r", label: "refresh" },
      { key: "Esc", label: "return" },
    ]}
    cols={120}
    height={36}
  />
);

export const K_InterruptedFailureHandoff80x24 = () => (
  <RouteScreen
    route="failure-handoff"
    title="EXECUTION INTERRUPTED"
    context="run patch-f0001 · target ./phase-target · terminal receipt persisted"
    rows={[
      { id: "outcome", cells: ["OUTCOME", "interrupted"], detail: "process lost after cancellation escalation" },
      { id: "truth", cells: ["TARGET", "unchanged"], detail: "application was not verified; no success claimed" },
      { id: "artifact", cells: ["ARTIFACT", "summary.json"], detail: ".kuzushi/v3/runs/patch-f0001" },
      { id: "trace", cells: ["TRACE", "trace.jsonl"], detail: "last durable event patch.apply.started" },
      { id: "next", cells: ["NEXT", "inspect trace"], detail: "then retry from the staged patch" },
    ]}
    selected={4}
    footer={[
      { key: "t", label: "trace" },
      { key: "r", label: "retry" },
      { key: "b", label: "return to Fix" },
      { key: "q", label: "quit" },
    ]}
    cols={80}
    height={24}
  />
);

export const L_VisualizationFallback80x24 = () => (
  <RouteScreen
    route="scene"
    title="VISUALIZATION · ATTACK PATH"
    context="contextual deck · real finding evidence only · Tab cycles five pages"
    rows={[
      { id: "source", cells: ["SOURCE", "routes/login.rs:84"], detail: "request parameter username" },
      { id: "flow1", cells: ["  ↓", "auth::login"], detail: "untrusted string enters query builder" },
      { id: "flow2", cells: ["  ↓", "db::query"], detail: "predicate assembled by concatenation" },
      { id: "sink", cells: ["SINK", "database execute"], detail: "F-0001 · critical · runtime verified" },
    ]}
    footer={[
      { key: "Tab", label: "next page" },
      { key: "Esc", label: "return to origin" },
    ]}
    cols={80}
    height={24}
  />
);
