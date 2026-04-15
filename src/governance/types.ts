/**
 * Governance types — scope policies, action tiers, and engagement rules.
 *
 * These controls must be in place before offensive modules
 * (blackbox, pentest, exploit) can ship safely.
 */

/** Action tiers ordered by risk level. */
export type ActionTier = "recon" | "scan" | "exploit" | "network" | "deploy" | "modify";

/** Tier risk ordering — lower index = safer. */
export const ACTION_TIER_ORDER: ActionTier[] = [
  "recon", "scan", "exploit", "network", "deploy", "modify",
];

/** Which tier a tool falls into — used to gate actions by autonomy level. */
export interface ToolTierMapping {
  /** Fully-qualified tool name (e.g. "blackbox:recon"). */
  toolName: string;
  tier: ActionTier;
}

/** Autonomy levels (from Sasoi). Higher = more autonomous. */
export type AutonomyLevel = "propose-only" | "human-in-loop" | "autonomous" | "full";

/**
 * Scope policy — defines what targets and actions are allowed
 * for a given engagement/workspace.
 */
export interface ScopePolicy {
  /** Allowed target patterns (repo paths, CIDRs, domains). Empty = allow all. */
  allowedTargets: string[];
  /** Explicitly denied target patterns. Takes precedence over allowed. */
  deniedTargets: string[];
  /** Maximum action tier allowed without explicit approval. */
  maxAutonomousTier: ActionTier;
  /** Per-module autonomy overrides. */
  moduleAutonomy?: Record<string, AutonomyLevel>;
  /** Budget cap in USD. Null = no limit. */
  budgetUsd: number | null;
  /** Whether to require explicit approval for actions above maxAutonomousTier. */
  requireApproval: boolean;
}

/** Full engagement rules combining scope + metadata. */
export interface EngagementRules {
  /** Unique engagement identifier. */
  engagementId: string;
  /** Who authorized this engagement. */
  authorizedBy: string;
  /** When the engagement window opens (ISO timestamp). */
  validFrom: string;
  /** When the engagement window closes (ISO timestamp). Null = no expiry. */
  validUntil: string | null;
  /** The scope policy for this engagement. */
  scope: ScopePolicy;
}

/** A single audit trail entry, written as JSONL. */
export interface AuditEntry {
  timestamp: string;
  /** Tool or action that was executed. */
  action: string;
  /** Action tier. */
  tier: ActionTier;
  /** Tool input (redacted if sensitive). */
  input: Record<string, unknown>;
  /** Whether the action was allowed. */
  allowed: boolean;
  /** Reason for denial, if blocked. */
  denialReason?: string;
  /** Cost in USD, if available. */
  costUsd?: number;
  /** Workspace ID, if applicable. */
  workspaceId?: string;
  /** Who/what initiated the action. */
  initiator: "user" | "agent" | "pipeline";
}

/** Result of an enforcement check. */
export interface EnforcementResult {
  allowed: boolean;
  reason?: string;
}

/** Default scope policy — permissive, suitable for local development. */
export function defaultScopePolicy(): ScopePolicy {
  return {
    allowedTargets: [],
    deniedTargets: [],
    maxAutonomousTier: "scan",
    budgetUsd: null,
    requireApproval: false,
  };
}
