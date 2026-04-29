export const TAINT_IRIS_NEXT_ID = "taint-iris-next" as const;
export const TAINT_IRIS_NEXT_DISPLAY_NAME = "Taint IRIS Next";

export const TAINT_IRIS_NEXT_SHORT_DESCRIPTION =
  "Agent-forward taint hunting inspired by the IRIS neuro-symbolic SAST paper. Uses Kuzushi context/threat modeling, structural extraction, scoped agents, and optional static-analysis backends.";

export const TAINT_IRIS_NEXT_ATTRIBUTION =
  "Inspired by \"IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities\" (Li, Dutta, Naik; ICLR 2025). This module adapts the paper's source/sink inference and taint-spec workflow to Kuzushi's context map, threat model, agent progress UI, and pluggable evidence backends. It is not affiliated with or endorsed by the IRIS authors.";

export const TAINT_IRIS_NEXT_REFERENCES = [
  { type: "URL", value: "https://openreview.net/forum?id=G3GvXMpzXM" },
  { type: "URL", value: "https://github.com/iris-sast/iris" },
] as const;

export const TAINT_IRIS_NEXT_TUI_HEADER_LINES = [
  "┌─ Taint IRIS Next ───────────────────────────────────────────────────────────┐",
  "│ inspired by IRIS, ICLR 2025 · Kuzushi agent-forward adaptation              │",
  "│ context loaded · threat model loaded · structural trace · backend auto       │",
  "└─────────────────────────────────────────────────────────────────────────────┘",
] as const;
