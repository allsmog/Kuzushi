import { PhaseCockpit } from "@kuzushi/tui-kit";

const rail = {
  map: "done",
  scan: "done",
  review: "current",
  prove: "pending",
  fix: "pending",
} as const;

const footer = {
  left: "route:run · 査 review 3/5 · ⛭ 掛 fix · workbench · openai:gpt-5.4",
  right: "6 findings / 1 crit / 2 high / 2 med",
  controls: [
    { key: "Ctrl+C", label: "request abort" },
    { key: "Esc", label: "prompt" },
  ],
} as const;

const mapSurfaces = [
  {
    id: "project-context",
    title: "PROJECT CONTEXT",
    state: "available",
    lines: [
      { text: "./phase-target · rev:unknown" },
      { text: "context:present · ⠋ context:build indexing repository context", tone: "success" },
      { text: "○ scope tree    no persisted nested scopes yet", tone: "muted" },
      { text: "◆ context feed  ./.kuzushi/context-snapshot.json" },
      { text: "◆ inventory     indexed=3 total=3 files · languages Rust" },
      { text: "◆ threat model  current threat model loaded" },
      { text: "◆ data flow     3 nodes · 2 flows · zones external/internal" },
      { text: "◆ review surface 6 items · 0 triaged · 6 pending" },
    ],
  },
  {
    id: "attack-surface",
    title: "ATTACK SURFACE · z terrain",
    state: "status",
    lines: [
      { text: "2 high/critical, max 91, tiers critical=1 high=1" },
      { text: "critical  Axum · POST /login · 91", tone: "danger" },
      { text: "high      Axum · GET /orders/:id · 72", tone: "warn" },
      { text: "▸ z open terrain visualization", tone: "accent" },
    ],
  },
  {
    id: "hot-modules",
    title: "HOT MODULES · z heatmap",
    state: "available",
    lines: [
      { text: "auth  12.0 · 1C 0H 1M 0L 0I", tone: "danger" },
      { text: "api    7.0 · 0C 1H 1M 0L 0I", tone: "warn" },
      { text: "web    5.0 · 0C 1H 0M 0L 0I", tone: "warn" },
      { text: "src    1.0 · 0C 0H 0M 1L 0I", tone: "muted" },
    ],
  },
] as const;

const scanSurfaces = [
  {
    id: "engines",
    title: "RECORDED ENGINE OUTCOMES",
    state: "available",
    lines: [
      { text: "✓ sast:scan · complete · r:scan-phase", tone: "success" },
      { text: "  semgrep · 24 rules · 4 candidates", tone: "muted" },
      { text: "  tree-sitter · 3 structural paths", tone: "muted" },
    ],
  },
  {
    id: "receipt",
    title: "SCAN RECEIPT",
    state: "available",
    lines: [
      { text: "outcome completed · revision not recorded" },
      { text: "result legacy inferred", tone: "warn" },
      { text: "run 1/1 scan-phase-run" },
      { text: "duration 12s · cost $0.0420" },
      { text: "> run sast:scan {}", tone: "accent" },
    ],
  },
  {
    id: "scope",
    title: "SCOPE / PLAN",
    state: "status",
    lines: [
      { text: "./phase-target" },
      { text: "recorded tool sast:scan" },
      { text: "include src/** · exclude target/**", tone: "muted" },
    ],
  },
] as const;

const reviewSurfaces = [
  {
    id: "queue",
    title: "REVIEW QUEUE",
    state: "available",
    lines: [
      { text: "F-0001  CRITICAL  SQL injection reaches query execution", selected: true },
      { text: "  F-0002  HIGH      Missing authorization on order lookup" },
      { text: "  F-0003  HIGH      Untrusted redirect target" },
      { text: "  F-0004  MEDIUM    Session cookie lacks SameSite" },
      { text: "  F-0005  MEDIUM    Verbose database error" },
      { text: "  F-0006  LOW       Server header disclosure" },
    ],
    footer: "6 candidates · 0 reviewed · filter all",
  },
  {
    id: "finding",
    title: "SELECTED FINDING",
    state: "status",
    lines: [
      { text: "F-0001 · CRITICAL · confidence 0.94", tone: "danger" },
      { text: "SQL injection reaches query execution" },
      { text: "source routes/login.rs:84" },
      { text: "sink db/query.rs:31 · evidence 2 sources" },
      { text: "decision pending · proof unverified", tone: "warn" },
      { text: "▸ Enter inspect · a accept · r reject", tone: "accent" },
    ],
  },
] as const;

const proveSurfaces = [
  {
    id: "proof-status",
    title: "PROOF STATUS",
    state: "status",
    lines: [
      { text: "F-0001 · SQL injection reaches query execution", tone: "danger" },
      { text: "STATUS runtime_verified · decision:needs_review" },
      { text: "EVIDENCE 1 source · observation current" },
      { text: "NEXT patch · patch F-0001", tone: "accent" },
    ],
  },
  {
    id: "evidence",
    title: "EVIDENCE",
    state: "available",
    lines: [
      { text: "attacker-controlled input reaches a database predicate" },
      { text: "payload ' OR 1=1 -- changed response from 401 to 200" },
      { text: "run verify-f0001 · artifact proof.json", tone: "success" },
    ],
  },
  {
    id: "ladder",
    title: "PROOF LADDER",
    state: "available",
    lines: [
      { text: "current [●●●] verified L4 · 1 source(s)", tone: "success" },
      { text: "L1 static path ✓ · L2 reachability ✓" },
      { text: "L3 controlled input ✓ · L4 runtime effect ✓" },
    ],
  },
] as const;

const fixSurfaces = [
  {
    id: "remediation",
    title: "REMEDIATION",
    state: "status",
    lines: [
      { text: "STATE  Staged for approval", tone: "warn" },
      { text: "▸ report", tone: "accent" },
      { text: "  choose format, completeness, and destination" },
      { text: "F-0001 · pending reviewed diff" },
      { text: "rationale: bind the user value as a query parameter" },
      { text: "side effect: preserves the login response schema" },
      { text: "✓ login_rejects_sqli · payload is inert", tone: "success" },
      { text: "guardrail: human approval required", tone: "warn" },
    ],
  },
  {
    id: "breakdown",
    title: "KUZUSHI · BREAKDOWN REPORT",
    state: "available",
    lines: [
      { text: "1 C · 2 H · 2 M · 1 L · 6 total · 0 fixed" },
      { text: "report sarif/all · preview only · no file written" },
      { text: "◆ F-0001  CRITICAL  SQL injection reaches query", tone: "danger" },
    ],
  },
  {
    id: "tree",
    title: "ATTACK TREE",
    state: "available",
    lines: [
      { text: "╭─ attacker goal — impact ─────────────╮" },
      { text: "╰──────────────────────────────────────╯" },
      { text: "                 │ ◇ OR — any one chain" },
      { text: "                 ▼" },
      { text: "Unauthenticated query manipulation · CRIT", tone: "danger" },
      { text: "  ◆ AND · supply crafted parameter" },
      { text: "          alter database predicate" },
    ],
  },
] as const;

const planByPhase = {
  map: {
    goal: "refresh repository context before scanning",
    summary: "Rebuild deterministic context and update the threat model.",
    tasks: [
      { id: "context", label: "context:build — refresh target inventory", selected: true },
      { id: "threat", label: "threat-model:build — update trust boundaries" },
    ],
  },
  scan: {
    goal: "scan the authenticated request boundary",
    summary: "Run the shared SAST plan against routes and database access.",
    tasks: [
      { id: "scan", label: "sast:scan — scan selected scope", selected: true },
      { id: "receipt", label: "runs show — retain the durable receipt" },
    ],
  },
  review: {
    goal: "review the critical and high-confidence candidates",
    summary: "Open each candidate and record a terminal disposition.",
    tasks: [
      { id: "critical", label: "open F-0001 — inspect source-backed evidence", selected: true },
      { id: "high", label: "open F-0002 — compare authority and reachability" },
    ],
  },
  prove: {
    goal: "strengthen proof for F-0001 without changing code",
    summary: "Replay the discovery run, then verify the selected finding.",
    tasks: [
      { id: "replay", label: "replay scan-phase-run — inspect durable evidence", selected: true },
      { id: "verify", label: "verify:finding F-0001 — collect runtime proof" },
      { id: "patch", label: "patch:finding F-0001 — out of Prove scope", skipped: true, state: "blocked" },
    ],
  },
  fix: {
    goal: "fix the verified SQL injection",
    summary: "Draft one parameterized-query patch and reverify after approval.",
    tasks: [
      { id: "draft", label: "patch:finding F-0001 — draft reviewed diff", selected: true },
      { id: "apply", label: "patch apply — requires operator approval" },
      { id: "verify", label: "verify:finding F-0001 — reverify applied patch" },
    ],
  },
} as const;

const common = {
  target: "./phase-target",
  reality: "review",
  context: "ctx:✓ built",
  status: "running",
  cost: "$0.37",
  model: "configured openai:gpt-5.4 [auth missing]",
  module: "context",
  rail,
  footer,
  prompt: { mode: "navigate" },
} as const;

export const A_CurrentMap120x36 = () => (
  <PhaseCockpit
    {...common}
    phase="map"
    next="record terminal dispositions for 6 of 6 remaining candidates"
    actions={[
      { key: "next", label: "continue Map" },
      { key: "context build", label: "build context" },
      { key: "z", label: "open visualization" },
    ]}
    surfaces={mapSurfaces}
    cols={120}
    rows={36}
  />
);

export const B_CurrentScan120x36 = () => (
  <PhaseCockpit
    {...common}
    phase="scan"
    next="record terminal dispositions for 6 of 6 remaining candidates"
    actions={[
      { key: "run sast:scan {}", label: "scan now" },
      { key: "jobs", label: "inspect run receipts" },
    ]}
    surfaces={scanSurfaces}
    cols={120}
    rows={36}
  />
);

export const C_CurrentReview120x36 = () => (
  <PhaseCockpit
    {...common}
    phase="review"
    next="record terminal dispositions for 6 of 6 remaining candidates"
    actions={[
      { key: "Enter", label: "inspect" },
      { key: "a/r", label: "accept/reject" },
      { key: "f", label: "filter" },
    ]}
    surfaces={reviewSurfaces}
    cols={120}
    rows={36}
  />
);

export const D_CurrentProve120x36 = () => (
  <PhaseCockpit
    {...common}
    phase="prove"
    next="verify F-0001 and retain the proof artifact"
    actions={[
      { key: "v", label: "verify selected" },
      { key: "t", label: "trace verification" },
    ]}
    surfaces={proveSurfaces}
    cols={120}
    rows={36}
  />
);

export const E_CurrentFix120x36 = () => (
  <PhaseCockpit
    {...common}
    phase="fix"
    next="approve the staged patch, then reverify F-0001"
    actions={[
      { key: "v", label: "reverify applied patch" },
      { key: "z", label: "chain / DFD" },
      { key: "report", label: "open Report" },
    ]}
    surfaces={fixSurfaces}
    cols={120}
    rows={36}
  />
);

export const F_CurrentMap40x12 = () => (
  <PhaseCockpit
    {...common}
    phase="map"
    next="record dispositions for 6 remaining candidates"
    surfaces={mapSurfaces}
    cols={40}
    rows={12}
  />
);

export const G_CurrentReview80x24 = () => (
  <PhaseCockpit
    {...common}
    phase="review"
    next="record terminal dispositions for 6 remaining candidates"
    surfaces={reviewSurfaces}
    cols={80}
    rows={24}
  />
);

export const H_CurrentFix160x48 = () => (
  <PhaseCockpit
    {...common}
    phase="fix"
    next="approve the staged patch, then reverify F-0001"
    surfaces={fixSurfaces}
    cols={160}
    rows={48}
  />
);

export const I_MapReturnedPlan = () => (
  <PhaseCockpit {...common} phase="map" next="review and apply the returned Map plan" surfaces={mapSurfaces} plan={{ ...planByPhase.map, returned: true, state: "completed" }} cols={80} rows={24} />
);

export const J_ScanReturnedPlan = () => (
  <PhaseCockpit {...common} phase="scan" next="review and apply the returned Scan plan" surfaces={scanSurfaces} plan={{ ...planByPhase.scan, returned: true, state: "completed" }} cols={80} rows={24} />
);

export const K_ReviewReturnedPlan = () => (
  <PhaseCockpit {...common} phase="review" next="review and apply the returned Review plan" surfaces={reviewSurfaces} plan={{ ...planByPhase.review, returned: true, state: "completed" }} cols={80} rows={24} />
);

export const L_ProveReturnedPlan = () => (
  <PhaseCockpit {...common} phase="prove" next="review and apply the supported Prove tasks" surfaces={proveSurfaces} plan={{ ...planByPhase.prove, returned: true, state: "partial" }} cols={80} rows={24} />
);

export const M_FixReturnedPlan = () => (
  <PhaseCockpit {...common} phase="fix" next="review and apply the returned Fix plan" surfaces={fixSurfaces} plan={{ ...planByPhase.fix, returned: true, state: "completed" }} cols={80} rows={24} />
);

export const N_PartialScanResult80x24 = () => (
  <PhaseCockpit
    {...common}
    phase="scan"
    status="idle"
    next="acknowledge the partial attempt or retry the missing CodeQL engine"
    result={{
      outcome: "partial",
      title: "PARTIAL · attempt scan-partial-02",
      detail: "Semgrep and tree-sitter completed · CodeQL unavailable · cost >=$0.041 incomplete",
      recommended: "acknowledge partial to continue, or open Jobs to retry CodeQL",
      controls: [
        { key: "a", label: "acknowledge" },
        { key: "j", label: "jobs" },
        { key: "t", label: "trace" },
      ],
    }}
    surfaces={scanSurfaces}
    cols={80}
    rows={24}
  />
);
