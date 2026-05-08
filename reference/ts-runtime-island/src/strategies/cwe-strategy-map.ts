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
      { strategyId: "dataflow-sqli", priority: 2, earlyExitThreshold: 0.9 },
      { strategyId: "reasoning-sqli", priority: 3, earlyExitThreshold: 0.85 },
      { strategyId: "execution-sqli", priority: 4, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-79"],
    vulnClass: "xss",
    strategies: [
      { strategyId: "syntactic-xss", priority: 1, earlyExitThreshold: 0.95 },
      { strategyId: "dataflow-xss", priority: 2, earlyExitThreshold: 0.9 },
      { strategyId: "reasoning-xss", priority: 3, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-918"],
    vulnClass: "ssrf",
    strategies: [
      { strategyId: "dataflow-ssrf", priority: 1, earlyExitThreshold: 0.9 },
      { strategyId: "reasoning-ssrf", priority: 2, earlyExitThreshold: 0.85 },
      { strategyId: "execution-ssrf", priority: 3, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-862", "CWE-863"],
    vulnClass: "auth-authz",
    strategies: [{ strategyId: "reasoning-auth", priority: 1, earlyExitThreshold: 0.0 }],
  },
  {
    cweIds: ["CWE-94", "CWE-95"],
    vulnClass: "code-injection",
    strategies: [
      { strategyId: "syntactic-code-injection", priority: 1, earlyExitThreshold: 0.95 },
      { strategyId: "dataflow-code-injection", priority: 2, earlyExitThreshold: 0.9 },
      { strategyId: "reasoning-code-injection", priority: 3, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-502"],
    vulnClass: "deserialization",
    strategies: [
      { strategyId: "syntactic-deserialization", priority: 1, earlyExitThreshold: 0.9 },
      { strategyId: "dataflow-deserialization", priority: 2, earlyExitThreshold: 0.85 },
      { strategyId: "reasoning-deserialization", priority: 3, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-78"],
    vulnClass: "os-command-injection",
    strategies: [
      { strategyId: "syntactic-command-injection", priority: 1, earlyExitThreshold: 0.95 },
      { strategyId: "dataflow-command-injection", priority: 2, earlyExitThreshold: 0.9 },
      { strategyId: "reasoning-command-injection", priority: 3, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-22"],
    vulnClass: "path-traversal",
    strategies: [
      { strategyId: "syntactic-path-traversal", priority: 1, earlyExitThreshold: 0.95 },
      { strategyId: "dataflow-path-traversal", priority: 2, earlyExitThreshold: 0.9 },
      { strategyId: "reasoning-path-traversal", priority: 3, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-943"],
    vulnClass: "nosql-injection",
    strategies: [
      { strategyId: "syntactic-nosql-injection", priority: 1, earlyExitThreshold: 0.95 },
      { strategyId: "dataflow-nosql-injection", priority: 2, earlyExitThreshold: 0.9 },
      { strategyId: "reasoning-nosql-injection", priority: 3, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-1336", "CWE-94"],
    vulnClass: "template-injection",
    strategies: [
      { strategyId: "syntactic-template-injection", priority: 1, earlyExitThreshold: 0.95 },
      { strategyId: "dataflow-template-injection", priority: 2, earlyExitThreshold: 0.9 },
      { strategyId: "reasoning-template-injection", priority: 3, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-1321"],
    vulnClass: "prototype-pollution",
    strategies: [
      { strategyId: "syntactic-prototype-pollution", priority: 1, earlyExitThreshold: 0.95 },
      { strategyId: "reasoning-prototype-pollution", priority: 2, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-362", "CWE-367"],
    vulnClass: "race-condition",
    strategies: [{ strategyId: "reasoning-race-condition", priority: 1, earlyExitThreshold: 0.0 }],
  },
  {
    cweIds: ["CWE-798", "CWE-327", "CWE-326"],
    vulnClass: "secrets-crypto",
    strategies: [
      { strategyId: "syntactic-secrets-crypto", priority: 1, earlyExitThreshold: 0.9 },
      { strategyId: "reasoning-secrets-crypto", priority: 2, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-829"],
    vulnClass: "supply-chain",
    strategies: [
      { strategyId: "syntactic-supply-chain", priority: 1, earlyExitThreshold: 0.9 },
      { strategyId: "reasoning-supply-chain", priority: 2, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-200", "CWE-400"],
    vulnClass: "graphql-security",
    strategies: [
      { strategyId: "reasoning-graphql-security", priority: 1, earlyExitThreshold: 0.0 },
    ],
  },
  {
    cweIds: ["CWE-611", "CWE-776"],
    vulnClass: "xxe",
    strategies: [
      { strategyId: "syntactic-xxe", priority: 1, earlyExitThreshold: 0.95 },
      { strategyId: "reasoning-xxe", priority: 2, earlyExitThreshold: 0.0 },
    ],
  },
];

/** Find the strategy profile for a given set of CWE IDs. */
export function findProfileForCwe(cweIds: string[]): CweStrategyProfile | undefined {
  const cweSet = new Set(cweIds);
  return CWE_STRATEGY_PROFILES.find((profile) => profile.cweIds.some((cwe) => cweSet.has(cwe)));
}
