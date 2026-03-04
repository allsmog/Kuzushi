const SEVERITY_SCORE: Record<string, number> = { ERROR: 3, WARNING: 2, INFO: 1 };
const LIKELIHOOD_SCORE: Record<string, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };
const IMPACT_SCORE: Record<string, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 };
const SUBCATEGORY_SCORE: Record<string, number> = { vuln: 2, audit: 1 };

/** Shared risk scoring used by all scanners. */
export function scoreFindingMetadata(input: {
  severity?: string;
  likelihood?: string;
  impact?: string;
  subcategory?: string[];
}): number {
  const severity = SEVERITY_SCORE[(input.severity ?? "INFO").toUpperCase()] ?? 1;
  const likelihood = LIKELIHOOD_SCORE[(input.likelihood ?? "LOW").toUpperCase()] ?? 1;
  const impact = IMPACT_SCORE[(input.impact ?? "LOW").toUpperCase()] ?? 1;
  const subcategories = input.subcategory ?? ["audit"];
  const subcategory = Math.max(...subcategories.map((s) => SUBCATEGORY_SCORE[s] ?? 0), 1);
  return severity * likelihood * impact * subcategory;
}
