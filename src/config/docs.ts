/**
 * Human-readable documentation for Kuzushi config keys.
 *
 * Drives `kuzushi config explain [key]`. Covers the keys most commonly set by
 * users — not an exhaustive schema. Rarely-tuned deep options live in
 * src/types.ts as typed fields and are out of scope for the `explain` surface.
 */

export interface ConfigKeyDoc {
  key: string;
  type: string;
  summary: string;
  default?: string;
  values?: string[];
  envVar?: string;
  details?: string;
}

export const CONFIG_KEY_DOCS: ConfigKeyDoc[] = [
  {
    key: "model",
    type: "string",
    summary: "Default LLM model for all AI operations (triage, verify, patch, etc.).",
    default: "anthropic:claude-sonnet-4-6",
    details:
      "Format: <provider>:<model-id>. Override per-stage with --task-model or via taskConfig.<task>.model in this file.",
  },
  {
    key: "agentRuntimeBackend",
    type: "enum",
    summary: "Which agent runtime drives LLM calls.",
    default: "pi-ai",
    values: ["pi-ai", "claude", "codex"],
  },
  {
    key: "agentRuntimeConfig.apiKey",
    type: "string (sensitive)",
    summary: "Plaintext provider API key. Strongly discouraged — use env vars or /auth instead.",
    envVar: "provider-specific, such as ANTHROPIC_API_KEY or OPENAI_API_KEY",
    details:
      "`kuzushi config set agentRuntimeConfig.apiKey ...` triggers a plaintext warning. Prefer /auth, provider env vars, or pass --api-key per invocation.",
  },
  {
    key: "busBackend",
    type: "enum",
    summary: "Message bus backend. Only `in-process` is implemented.",
    default: "in-process",
    values: ["in-process"],
  },
  {
    key: "tasks",
    type: "string[]",
    summary: "Task IDs to run in the scan pipeline.",
    details:
      "Use `kuzushi task list` to see what's registered. Preset flags (--preset) populate this.",
  },
  {
    key: "severity",
    type: "string[]",
    summary: "Severity levels to surface.",
    default: '["ERROR", "WARNING"]',
    values: ["ERROR", "WARNING", "INFO"],
  },
  {
    key: "excludePatterns",
    type: "string[]",
    summary: "Directory/glob patterns to skip during scan.",
    default: '["test", "tests", "node_modules", "dist", "build", ".next"]',
  },
  {
    key: "verify",
    type: "boolean",
    summary: "Enable post-triage exploitability verification.",
    default: "false",
  },
  {
    key: "pocHarness",
    type: "boolean",
    summary: "Generate PoC exploit harnesses for verified findings. Requires verify=true.",
    default: "false",
  },
  {
    key: "triageBatchSize",
    type: "number",
    summary: "Findings per triage agent invocation.",
    default: "5",
  },
  {
    key: "triageConcurrency",
    type: "number",
    summary: "Max concurrent triage workers.",
    default: "5",
  },
  {
    key: "scanMode",
    type: "enum",
    summary: "Scanner execution strategy.",
    default: "concurrent",
    values: ["concurrent", "sequential"],
  },
  {
    key: "taskConfig",
    type: "object",
    summary: "Per-task overrides (model, effort, maxFindings, etc.) keyed by task ID.",
    details:
      'Example: `taskConfig["vuln-scout"] = { model: "anthropic:claude-opus-4-7", maxFindings: 100 }`.',
  },
  {
    key: "qualityGates.failOnExploitable",
    type: "boolean",
    summary: "Fail the run when a verified-exploitable finding is produced.",
    default: "false",
  },
  {
    key: "qualityGates.maxCriticalFindings",
    type: "number",
    summary: "Fail the run when the critical-finding count exceeds this threshold.",
  },
  {
    key: "monorepo.mode",
    type: "enum",
    summary: "Monorepo discovery behaviour.",
    default: "auto",
    values: ["auto", "off"],
  },
  {
    key: "monorepo.maxModules",
    type: "number",
    summary: "Upper bound on modules scanned in Phase 2 of monorepo discovery.",
  },
];

export function explainConfigKey(key: string): ConfigKeyDoc | null {
  return CONFIG_KEY_DOCS.find((doc) => doc.key === key) ?? null;
}

export function listConfigKeys(): Array<{
  key: string;
  type: string;
  default?: string;
  summary: string;
}> {
  return CONFIG_KEY_DOCS.map((doc) => ({
    key: doc.key,
    type: doc.type,
    default: doc.default,
    summary: doc.summary,
  }));
}
