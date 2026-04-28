import type {
  DreadRiskScores,
  DreadThreatScore,
  StrideThreat,
  ThreatModelDocument,
  ThreatModelMethodology,
} from "./types.js";

const VALID_METHODOLOGIES = new Set<ThreatModelMethodology>(["pasta", "stride", "dread"]);

export function normalizeThreatModelMethodology(
  value: unknown,
  fallback: ThreatModelMethodology = "pasta",
): ThreatModelMethodology {
  if (typeof value !== "string") return fallback;
  const normalized = value.trim().toLowerCase();
  return VALID_METHODOLOGIES.has(normalized as ThreatModelMethodology)
    ? (normalized as ThreatModelMethodology)
    : fallback;
}

export function applyThreatModelMethodology(
  document: ThreatModelDocument,
  methodology: ThreatModelMethodology,
): ThreatModelDocument {
  const next: ThreatModelDocument = {
    ...document,
    methodology,
  };

  if (methodology === "dread") {
    return {
      ...next,
      riskScores: buildDreadRiskScores(document.threats),
    };
  }

  return next;
}

export function buildDreadRiskScores(threats: StrideThreat[]): DreadRiskScores {
  return {
    methodology: "dread",
    scale: "0-10",
    threats: threats.map(scoreThreatWithDread),
  };
}

function scoreThreatWithDread(threat: StrideThreat): DreadThreatScore {
  const damage = impactScore(threat.impact);
  const reproducibility = likelihoodScore(threat.likelihood);
  const exploitability = exploitabilityScore(threat);
  const affectedUsers = affectedUsersScore(threat);
  const discoverability = discoverabilityScore(threat);
  const score = round1(
    (damage + reproducibility + exploitability + affectedUsers + discoverability) / 5,
  );

  return {
    threatId: threat.id,
    damage,
    reproducibility,
    exploitability,
    affectedUsers,
    discoverability,
    score,
    rating: dreadRating(score),
    rationale: [
      `Damage follows impact=${threat.impact}.`,
      `Reproducibility follows likelihood=${threat.likelihood}.`,
      threat.evidenceAnchors && threat.evidenceAnchors.length > 0
        ? `Discoverability is raised by ${threat.evidenceAnchors.length} concrete evidence anchor(s).`
        : "Discoverability is lower because no direct evidence anchors were recorded.",
    ],
  };
}

function impactScore(impact: StrideThreat["impact"]): number {
  switch (impact) {
    case "critical":
      return 10;
    case "high":
      return 8;
    case "medium":
      return 5;
    case "low":
      return 2;
  }
}

function likelihoodScore(likelihood: StrideThreat["likelihood"]): number {
  switch (likelihood) {
    case "high":
      return 8;
    case "medium":
      return 5;
    case "low":
      return 2;
  }
}

function exploitabilityScore(threat: StrideThreat): number {
  const preconditions = threat.preconditions.length;
  if (preconditions === 0) return 8;
  if (preconditions <= 2) return 6;
  return 4;
}

function affectedUsersScore(threat: StrideThreat): number {
  if (threat.impact === "critical") return 9;
  if (threat.impact === "high") return 7;
  if (threat.category === "denial-of-service" || threat.category === "information-disclosure") {
    return 6;
  }
  return 4;
}

function discoverabilityScore(threat: StrideThreat): number {
  const anchors = threat.evidenceAnchors?.length ?? 0;
  if (anchors >= 3) return 8;
  if (anchors > 0) return 6;
  return 3;
}

function dreadRating(score: number): DreadThreatScore["rating"] {
  if (score >= 8.5) return "critical";
  if (score >= 6.5) return "high";
  if (score >= 4) return "medium";
  return "low";
}

function round1(value: number): number {
  return Math.round(value * 10) / 10;
}
