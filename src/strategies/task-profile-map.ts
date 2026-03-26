import { type CweStrategyProfile, CWE_STRATEGY_PROFILES } from "./cwe-strategy-map.js";

/** Maps detection task IDs to their primary CWE IDs for strategy profile lookup. */
const TASK_CWE_MAP: Record<string, string[]> = {
  "ssrf-detect": ["CWE-918"],
  "nosql-injection-detect": ["CWE-943"],
  "template-injection-detect": ["CWE-1336", "CWE-94"],
  "prototype-pollution-detect": ["CWE-1321"],
  "race-condition-detect": ["CWE-362", "CWE-367"],
  "secrets-crypto-detect": ["CWE-798", "CWE-327", "CWE-326"],
  "supply-chain-detect": ["CWE-829"],
  "graphql-security-detect": ["CWE-200", "CWE-400"],
  "command-injection-detect": ["CWE-78"],
  "xxe-detect": ["CWE-611"],
  "deserialization-detect": ["CWE-502"],
};

/** Look up the strategy profile for a detection task. */
export function getProfileForTask(taskId: string): CweStrategyProfile | undefined {
  const cweIds = TASK_CWE_MAP[taskId];
  if (!cweIds) return undefined;

  const cweSet = new Set(cweIds);
  return CWE_STRATEGY_PROFILES.find((profile) =>
    profile.cweIds.some((cwe) => cweSet.has(cwe)),
  );
}

/** All task IDs eligible for multi-strategy wrapping. */
export const MULTI_STRATEGY_TASK_IDS = Object.keys(TASK_CWE_MAP);
