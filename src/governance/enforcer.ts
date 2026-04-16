/**
 * Governance enforcer — pre-execution checks for target scope,
 * budget limits, and action tier approval.
 */

import type {
  ActionTier,
  AuditEntry,
  EnforcementResult,
  ScopePolicy,
  ToolTierMapping,
} from "./types.js";
import { ACTION_TIER_ORDER } from "./types.js";

/** Default tool → tier mappings. Modules can register additional mappings. */
const DEFAULT_TOOL_TIERS: ToolTierMapping[] = [
  // SAST tools — all safe scan-tier
  { toolName: "sast:context", tier: "recon" },
  { toolName: "sast:scan", tier: "scan" },
  { toolName: "sast:semgrep", tier: "scan" },
  { toolName: "sast:codeql", tier: "scan" },
  { toolName: "sast:agentic", tier: "scan" },
  { toolName: "sast:threat-hunt", tier: "scan" },
  { toolName: "sast:taint-iris", tier: "scan" },
  { toolName: "sast:triage", tier: "scan" },
  { toolName: "sast:verify", tier: "scan" },
  { toolName: "sast:patch", tier: "modify" },
  { toolName: "sast:findings", tier: "recon" },
];

export class GovernanceEnforcer {
  private toolTiers = new Map<string, ActionTier>();
  private cumulativeCostUsd = 0;

  constructor(private scope: ScopePolicy) {
    for (const mapping of DEFAULT_TOOL_TIERS) {
      this.toolTiers.set(mapping.toolName, mapping.tier);
    }
  }

  /** Register a tool's action tier (called when external modules load). */
  registerToolTier(toolName: string, tier: ActionTier): void {
    this.toolTiers.set(toolName, tier);
  }

  /** Get the action tier for a tool. Defaults to "scan" if unregistered. */
  getToolTier(toolName: string): ActionTier {
    return this.toolTiers.get(toolName) ?? "scan";
  }

  /** Record cost from a completed tool execution. */
  addCost(costUsd: number): void {
    this.cumulativeCostUsd += costUsd;
  }

  /** Get cumulative cost across this session. */
  getCumulativeCost(): number {
    return this.cumulativeCostUsd;
  }

  /** Update the scope policy (e.g. when loading a new engagement rules file). */
  updateScope(scope: ScopePolicy): void {
    this.scope = scope;
  }

  /**
   * Check whether a tool execution is allowed under the current scope policy.
   * Returns an enforcement result with reason if denied.
   */
  checkExecution(toolName: string, target?: string): EnforcementResult {
    // Check target scope
    if (target) {
      const targetResult = this.checkTarget(target);
      if (!targetResult.allowed) return targetResult;
    }

    // Check action tier
    const tier = this.getToolTier(toolName);
    const tierResult = this.checkTier(tier);
    if (!tierResult.allowed) return tierResult;

    // Check budget
    const budgetResult = this.checkBudget();
    if (!budgetResult.allowed) return budgetResult;

    return { allowed: true };
  }

  /** Check if a target is within scope. */
  checkTarget(target: string): EnforcementResult {
    // Denied targets always take precedence
    if (this.scope.deniedTargets.length > 0) {
      for (const pattern of this.scope.deniedTargets) {
        if (matchesTarget(target, pattern)) {
          return {
            allowed: false,
            reason: `Target "${target}" is explicitly denied by scope policy.`,
          };
        }
      }
    }

    // If allowed targets are specified, target must match at least one
    if (this.scope.allowedTargets.length > 0) {
      const matches = this.scope.allowedTargets.some((pattern) => matchesTarget(target, pattern));
      if (!matches) {
        return {
          allowed: false,
          reason: `Target "${target}" is not in the allowed scope. Allowed: ${this.scope.allowedTargets.join(", ")}`,
        };
      }
    }

    return { allowed: true };
  }

  /** Check if an action tier is allowed. */
  checkTier(tier: ActionTier): EnforcementResult {
    const maxIndex = ACTION_TIER_ORDER.indexOf(this.scope.maxAutonomousTier);
    const tierIndex = ACTION_TIER_ORDER.indexOf(tier);

    if (tierIndex > maxIndex && this.scope.requireApproval) {
      return {
        allowed: false,
        reason: `Action tier "${tier}" exceeds max autonomous tier "${this.scope.maxAutonomousTier}". Approval required.`,
      };
    }

    return { allowed: true };
  }

  /** Check if budget has been exceeded. */
  checkBudget(): EnforcementResult {
    if (this.scope.budgetUsd !== null && this.cumulativeCostUsd >= this.scope.budgetUsd) {
      return {
        allowed: false,
        reason: `Budget exceeded: $${this.cumulativeCostUsd.toFixed(2)} / $${this.scope.budgetUsd.toFixed(2)}`,
      };
    }

    return { allowed: true };
  }

  /** Build an audit entry for a tool execution. */
  buildAuditEntry(
    toolName: string,
    input: Record<string, unknown>,
    result: EnforcementResult,
    opts?: { costUsd?: number; workspaceId?: string; initiator?: AuditEntry["initiator"] },
  ): AuditEntry {
    return {
      timestamp: new Date().toISOString(),
      action: toolName,
      tier: this.getToolTier(toolName),
      input: redactSensitiveFields(input),
      allowed: result.allowed,
      denialReason: result.reason,
      costUsd: opts?.costUsd,
      workspaceId: opts?.workspaceId,
      initiator: opts?.initiator ?? "user",
    };
  }
}

/** Simple target matching: prefix match for paths, exact match otherwise. */
function matchesTarget(target: string, pattern: string): boolean {
  // Path prefix match
  if (pattern.startsWith("./") || pattern.startsWith("/")) {
    return target.startsWith(pattern) || target === pattern;
  }
  // CIDR or domain — exact match for now
  return target === pattern;
}

/** Redact fields that might contain secrets. */
function redactSensitiveFields(input: Record<string, unknown>): Record<string, unknown> {
  const SENSITIVE_KEYS = new Set(["apiKey", "token", "password", "secret", "credential"]);
  const redacted: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (SENSITIVE_KEYS.has(key)) {
      redacted[key] = "[REDACTED]";
    } else {
      redacted[key] = value;
    }
  }
  return redacted;
}
