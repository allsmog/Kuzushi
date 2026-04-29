import { normalizeTaskCapabilityIds } from "../capabilities.js";

export interface DagIdResolver {
  resolveName(id: string): string;
}

export function normalizeDagIds(ids: string[], resolver?: DagIdResolver): string[] {
  const seen = new Set<string>();
  const normalizedIds: string[] = [];

  for (const rawId of normalizeTaskCapabilityIds(ids)) {
    const id = resolver?.resolveName(rawId) ?? canonicalDagId(rawId.trim());
    if (!id || seen.has(id)) continue;
    seen.add(id);
    normalizedIds.push(id);
  }

  return normalizedIds;
}

export function canonicalDagId(id: string): string {
  return CANONICAL_DAG_IDS[id] ?? id;
}

const CANONICAL_DAG_IDS: Record<string, string> = {
  semgrep: "semgrep:scan",
  codeql: "codeql:scan",
  agentic: "agentic-sast:scan",
  "agentic-sast": "agentic-sast:scan",
  "carlini-threat-hunt": "carlini-threat-hunt:run",
  "taint-cwe-select": "pipeline:taint-cwe-select",
  "taint-iris": "taint-iris:hunt",
  "task-selector": "pipeline:task-selector",
  "approval-gate": "pipeline:approval-gate",
  "context-gatherer": "context:context-gatherer",
  "context-enricher": "context:context-enricher",
  "app-model-build": "context:app-model-build",
  "code-config-detect": "context:code-config-detect",
  "call-graph-assist": "context:call-graph-assist",
  "code-graph-build": "context:code-graph-build",
  "code-graph-enrich": "context:code-graph-enrich",
  "invariant-extract": "context:invariant-extract",
  "invariant-check": "context:invariant-check",
  "threat-model-randori": "threat-model:threat-model-randori",
  "threat-scenario-build": "threat-model:threat-scenario-build",
  "ssrf-detect": "agentic-sast:ssrf-detect",
  "nosql-injection-detect": "agentic-sast:nosql-injection-detect",
  "command-injection-detect": "agentic-sast:command-injection-detect",
  "template-injection-detect": "agentic-sast:template-injection-detect",
  "deserialization-detect": "agentic-sast:deserialization-detect",
  "xxe-detect": "agentic-sast:xxe-detect",
  "prototype-pollution-detect": "agentic-sast:prototype-pollution-detect",
  "graphql-security-detect": "agentic-sast:graphql-security-detect",
  "secrets-crypto-detect": "agentic-sast:secrets-crypto-detect",
  "race-condition-detect": "agentic-sast:race-condition-detect",
  "sharp-edges-detect": "agentic-sast:sharp-edges-detect",
  "supply-chain-detect": "agentic-sast:supply-chain-detect",
  "auth-logic-detect": "agentic-sast:auth-logic-detect",
  "crypto-behavioral-test": "agentic-sast:crypto-behavioral-test",
  "reachability-check": "agentic-sast:reachability-check",
  "diff-review": "agentic-sast:diff-review",
  "systems-context-gatherer": "systems-hunt:systems-context-gatherer",
  "systems-invariant-extract": "systems-hunt:systems-invariant-extract",
  "systems-trigger-synth": "systems-hunt:systems-trigger-synth",
  "systems-hunt": "systems-hunt:systems-hunt",
  "deep-semantic-cwe-select": "systems-hunt:deep-semantic-cwe-select",
  "deep-semantic-hunt": "systems-hunt:deep-semantic-hunt",
  "tob-audit": "tob:tob-audit",
  "vuln-scout": "vuln-scout:vuln-scout",
};
