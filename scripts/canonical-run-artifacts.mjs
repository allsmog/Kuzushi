export const requiredRunArtifactSpecs = [
  { path: "run.json", label: "run metadata", kind: "json" },
  { path: "events.jsonl", label: "run events", kind: "jsonl" },
  { path: "trace.jsonl", label: "runtime trace", kind: "jsonl" },
  { path: "context.json", label: "context snapshot", kind: "json" },
  { path: "attack-surface.json", label: "attack surface", kind: "json" },
  { path: "threat-model.json", label: "threat model", kind: "json" },
  { path: "recommendations.json", label: "recommendations", kind: "json" },
  { path: "findings.json", label: "findings", kind: "json" },
  { path: "proof.json", label: "proof", kind: "json" },
  { path: "failures.json", label: "failure handoff", kind: "json" },
  { path: "report.md", label: "report", kind: "markdown" },
  { path: "artifacts.json", label: "artifact manifest", kind: "json" },
];

export const requiredRunArtifacts = requiredRunArtifactSpecs.map((artifact) => artifact.path);

export const optionalRunArtifactSpecs = [
  { path: "report.sarif", label: "SARIF report", kind: "sarif" },
];

export const toolResultArtifactSpecs = [
  { path: "result.json", label: "tool result", kind: "json" },
];

export const optionalRunArtifacts = optionalRunArtifactSpecs.map((artifact) => artifact.path);
export const toolResultArtifacts = toolResultArtifactSpecs.map((artifact) => artifact.path);
