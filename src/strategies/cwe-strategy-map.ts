/** CWE-to-strategy profiles defining which strategies run for each vulnerability class. */

export interface CweStrategyProfile {
  cweIds: string[];
  vulnClass: string;
  strategies: Array<{
    strategyId: string;
    priority: number;
    earlyExitThreshold: number;
  }>;
}

export const CWE_STRATEGY_PROFILES: CweStrategyProfile[] = [
  {
    cweIds: ["CWE-89"],
    vulnClass: "sql-injection",
    strategies: [
      { strategyId: "syntactic-sqli", priority: 1, earlyExitThreshold: 0.95 },
      { strategyId: "dataflow-sqli", priority: 2, earlyExitThreshold: 0.90 },
      { strategyId: "reasoning-sqli", priority: 3, earlyExitThreshold: 0.85 },
      { strategyId: "execution-sqli", priority: 4, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-79"],
    vulnClass: "xss",
    strategies: [
      { strategyId: "syntactic-xss", priority: 1, earlyExitThreshold: 0.95 },
      { strategyId: "dataflow-xss", priority: 2, earlyExitThreshold: 0.90 },
      { strategyId: "reasoning-xss", priority: 3, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-918"],
    vulnClass: "ssrf",
    strategies: [
      { strategyId: "dataflow-ssrf", priority: 1, earlyExitThreshold: 0.90 },
      { strategyId: "reasoning-ssrf", priority: 2, earlyExitThreshold: 0.85 },
      { strategyId: "execution-ssrf", priority: 3, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-862", "CWE-863"],
    vulnClass: "auth-authz",
    strategies: [
      { strategyId: "reasoning-auth", priority: 1, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-94", "CWE-95"],
    vulnClass: "code-injection",
    strategies: [
      { strategyId: "syntactic-code-injection", priority: 1, earlyExitThreshold: 0.95 },
      { strategyId: "dataflow-code-injection", priority: 2, earlyExitThreshold: 0.90 },
      { strategyId: "reasoning-code-injection", priority: 3, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-502"],
    vulnClass: "deserialization",
    strategies: [
      { strategyId: "syntactic-deserialization", priority: 1, earlyExitThreshold: 0.90 },
      { strategyId: "dataflow-deserialization", priority: 2, earlyExitThreshold: 0.85 },
      { strategyId: "reasoning-deserialization", priority: 3, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-78"],
    vulnClass: "os-command-injection",
    strategies: [
      { strategyId: "syntactic-command-injection", priority: 1, earlyExitThreshold: 0.95 },
      { strategyId: "dataflow-command-injection", priority: 2, earlyExitThreshold: 0.90 },
      { strategyId: "reasoning-command-injection", priority: 3, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-22"],
    vulnClass: "path-traversal",
    strategies: [
      { strategyId: "syntactic-path-traversal", priority: 1, earlyExitThreshold: 0.95 },
      { strategyId: "dataflow-path-traversal", priority: 2, earlyExitThreshold: 0.90 },
      { strategyId: "reasoning-path-traversal", priority: 3, earlyExitThreshold: 0.0 },
    ],
  },
];

/** Find the strategy profile for a given set of CWE IDs. */
export function findProfileForCwe(cweIds: string[]): CweStrategyProfile | undefined {
  const cweSet = new Set(cweIds);
  return CWE_STRATEGY_PROFILES.find((profile) =>
    profile.cweIds.some((cwe) => cweSet.has(cwe)),
  );
}
