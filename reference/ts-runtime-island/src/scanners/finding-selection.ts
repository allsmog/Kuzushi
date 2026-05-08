import { capFindingsForTriage, clusterFindings } from "./normalization.js";
import type { Finding } from "./types.js";

/**
 * Legacy helper retained for callers/tests that still import finding-selection.
 * The live pipeline now uses the same clustered normalization path everywhere.
 */
export function selectTopFindings(findings: Finding[], maxFindings?: number): Finding[] {
  const clustered = clusterFindings(findings);
  return capFindingsForTriage(clustered.findings, maxFindings);
}
