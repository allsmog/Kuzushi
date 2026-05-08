/**
 * Trajectory memory: records the sequence of tool calls and outcomes from each
 * triage investigation. On future runs, injects relevant exemplar trajectories
 * into the triage prompt so agents learn from prior successful/failed approaches.
 */

import type Database from "better-sqlite3";
import type { AgentActivity } from "./agent-runtime/execution.js";
import { safeJsonParse, safeJsonStringify } from "./utils/safe-json.js";

/** A single tool-call step recorded during triage. */
export interface TrajectoryStep {
  toolName: string;
  toolInput: Record<string, unknown>;
  outcome: string;
}

/** A full trajectory record persisted in SQLite. */
export interface TrajectoryRecord {
  id: string;
  ruleId: string;
  cwesJson: string;
  verdict: string;
  wasCorrect: number | null;
  stepsJson: string;
  summary: string;
  fingerprint: string | null;
  createdAt: string;
  updatedAt: string;
}

/**
 * Collects agent activity events into a trajectory during triage.
 */
export class TrajectoryCollector {
  private steps: TrajectoryStep[] = [];
  private pendingTool: { toolName: string; toolInput: Record<string, unknown> } | null = null;

  /** Wrap an existing activityCallback to also collect trajectory steps. */
  wrapCallback(
    original?: (activity: AgentActivity) => Promise<void> | void,
  ): (activity: AgentActivity) => Promise<void> | void {
    return async (activity: AgentActivity) => {
      this.onActivity(activity);
      if (original) {
        await original(activity);
      }
    };
  }

  /** Process a single activity event. */
  onActivity(activity: AgentActivity): void {
    if (activity.kind === "tool-start" && activity.toolName) {
      this.pendingTool = {
        toolName: activity.toolName,
        toolInput: summarizeToolInput(activity.toolInput ?? {}),
      };
    } else if (activity.kind === "tool-complete" && this.pendingTool) {
      this.steps.push({
        toolName: this.pendingTool.toolName,
        toolInput: this.pendingTool.toolInput,
        outcome: activity.summary ?? "completed",
      });
      this.pendingTool = null;
    }
  }

  /** Return the collected steps. */
  getSteps(): TrajectoryStep[] {
    return [...this.steps];
  }

  /** Return number of collected steps. */
  get length(): number {
    return this.steps.length;
  }
}

/**
 * Summarize tool input for storage — keep only file paths and patterns,
 * not full file contents or large payloads.
 */
function summarizeToolInput(input: Record<string, unknown>): Record<string, unknown> {
  const summary: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (typeof value === "string" && value.length > 200) {
      summary[key] = `${value.slice(0, 200)}...`;
    } else {
      summary[key] = value;
    }
  }
  return summary;
}

/**
 * Generate a 2-3 sentence strategy summary from trajectory steps.
 */
export function summarizeTrajectory(steps: TrajectoryStep[], verdict: string): string {
  if (steps.length === 0) {
    return `Verdict: ${verdict}. No tool calls recorded.`;
  }

  const toolNames = [...new Set(steps.map((s) => s.toolName))];
  const firstStep = steps[0];
  const lastStep = steps[steps.length - 1];

  return [
    `Used ${toolNames.join(", ")} across ${steps.length} steps.`,
    `Started by ${firstStep.toolName}(${safeJsonStringify(Object.values(firstStep.toolInput)[0] ?? "").slice(0, 60)}).`,
    `Final step: ${lastStep.toolName} → ${lastStep.outcome.slice(0, 100)}.`,
    `Verdict: ${verdict}.`,
  ].join(" ");
}

/**
 * Save a trajectory record after triage completes.
 */
export function saveTrajectory(
  db: Database.Database,
  trajectory: {
    id: string;
    ruleId: string;
    cwes: string[];
    verdict: string;
    steps: TrajectoryStep[];
    summary: string;
    fingerprint: string | null;
  },
): void {
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO trajectories (
      id, rule_id, cwes_json, verdict,
      was_correct, steps_json, summary, fingerprint,
      created_at, updated_at
    ) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?, ?)
  `).run(
    trajectory.id,
    trajectory.ruleId,
    safeJsonStringify(trajectory.cwes),
    trajectory.verdict,
    safeJsonStringify(trajectory.steps),
    trajectory.summary,
    trajectory.fingerprint,
    now,
    now,
  );

  // Prune: keep at most 50 trajectories per rule_id
  pruneTrajectories(db, trajectory.ruleId, 50);
}

/**
 * Update the was_correct flag on trajectories matching a fingerprint.
 */
export function updateTrajectoryCorrectness(
  db: Database.Database,
  fingerprint: string,
  wasCorrect: boolean,
): void {
  db.prepare(`
    UPDATE trajectories
    SET was_correct = ?, updated_at = ?
    WHERE fingerprint = ?
  `).run(wasCorrect ? 1 : 0, new Date().toISOString(), fingerprint);
}

/**
 * Retrieve relevant exemplar trajectories for a given rule_id and CWE list.
 * Priority: exact rule_id match (verified correct) > same CWE (verified) > unverified.
 * Skips was_correct = 0 trajectories.
 */
export function retrieveTrajectories(
  db: Database.Database,
  ruleId: string,
  cwes: string[],
  maxExemplars: number,
): TrajectoryRecord[] {
  if (maxExemplars <= 0) {
    return [];
  }

  const results: TrajectoryRecord[] = [];

  // 1. Exact rule_id match, verified correct
  const exactCorrect = db
    .prepare(`
    SELECT * FROM trajectories
    WHERE rule_id = ? AND was_correct = 1
    ORDER BY updated_at DESC
    LIMIT ?
  `)
    .all(ruleId, maxExemplars) as TrajectoryRecord[];
  results.push(...exactCorrect);

  if (results.length >= maxExemplars) {
    return results.slice(0, maxExemplars);
  }

  // 2. Same CWE family, verified correct
  if (cwes.length > 0) {
    const remaining = maxExemplars - results.length;
    const existingIds = new Set(results.map((r) => r.id));

    for (const cwe of cwes) {
      if (results.length >= maxExemplars) break;
      const cweRows = db
        .prepare(`
        SELECT * FROM trajectories
        WHERE cwes_json LIKE ? AND was_correct = 1 AND rule_id != ?
        ORDER BY updated_at DESC
        LIMIT ?
      `)
        .all(`%${cwe}%`, ruleId, remaining) as TrajectoryRecord[];

      for (const row of cweRows) {
        if (!existingIds.has(row.id) && results.length < maxExemplars) {
          results.push(row);
          existingIds.add(row.id);
        }
      }
    }
  }

  if (results.length >= maxExemplars) {
    return results.slice(0, maxExemplars);
  }

  // 3. Same CWE family, unverified
  if (cwes.length > 0) {
    const remaining = maxExemplars - results.length;
    const existingIds = new Set(results.map((r) => r.id));

    for (const cwe of cwes) {
      if (results.length >= maxExemplars) break;
      const unverified = db
        .prepare(`
        SELECT * FROM trajectories
        WHERE cwes_json LIKE ? AND was_correct IS NULL
        ORDER BY updated_at DESC
        LIMIT ?
      `)
        .all(`%${cwe}%`, remaining) as TrajectoryRecord[];

      for (const row of unverified) {
        if (!existingIds.has(row.id) && results.length < maxExemplars) {
          results.push(row);
          existingIds.add(row.id);
        }
      }
    }
  }

  return results.slice(0, maxExemplars);
}

/**
 * Format retrieved trajectories into a prompt section for injection.
 */
export function formatTrajectoriesForPrompt(trajectories: TrajectoryRecord[]): string {
  if (trajectories.length === 0) {
    return "";
  }

  const sections = trajectories.map((t, idx) => {
    const verifiedTag =
      t.wasCorrect === 1
        ? " [VERIFIED CORRECT]"
        : t.wasCorrect === 0
          ? " [VERIFIED INCORRECT]"
          : "";

    const parsedSteps = safeJsonParse<unknown>(t.stepsJson, []);
    const steps: TrajectoryStep[] = Array.isArray(parsedSteps)
      ? (parsedSteps as TrajectoryStep[])
      : [];

    const stepsStr = steps
      .slice(0, 5)
      .map(
        (s, i) =>
          `${i + 1}. ${s.toolName}(${safeJsonStringify(Object.values(s.toolInput)[0] ?? "").slice(0, 60)}) → ${s.outcome.slice(0, 80)}`,
      )
      .join("\n");

    return [
      `### Exemplar ${idx + 1} (rule: ${t.ruleId}, verdict: ${t.verdict})${verifiedTag}`,
      `Summary: ${t.summary}`,
      `Steps:`,
      stepsStr,
    ].join("\n");
  });

  return ["## Prior Investigation Exemplars", ...sections].join("\n\n");
}

/**
 * Compute historical accuracy rate for a specialist role on a given rule family.
 * Returns accuracy as a number in [0, 1], or undefined if no data available.
 */
export function getSpecialistAccuracy(
  db: Database.Database,
  ruleId: string,
  role: string,
): number | undefined {
  // Query trajectories that have been verified (was_correct IS NOT NULL)
  // and match the rule pattern
  const rows = db
    .prepare(`
    SELECT was_correct FROM trajectories
    WHERE rule_id = ? AND was_correct IS NOT NULL
    ORDER BY updated_at DESC
    LIMIT 20
  `)
    .all(ruleId) as Array<{ was_correct: number }>;

  if (rows.length < 3) {
    return undefined;
  }

  const correct = rows.filter((r) => r.was_correct === 1).length;
  return correct / rows.length;
}

/**
 * Prune old trajectories for a rule_id, keeping the newest N.
 */
function pruneTrajectories(db: Database.Database, ruleId: string, maxPerRule: number): void {
  db.prepare(`
    DELETE FROM trajectories
    WHERE rule_id = ? AND id NOT IN (
      SELECT id FROM trajectories
      WHERE rule_id = ?
      ORDER BY updated_at DESC
      LIMIT ?
    )
  `).run(ruleId, ruleId, maxPerRule);
}

/**
 * Prune unverified trajectories older than the given number of days.
 */
export function pruneOldUnverifiedTrajectories(
  db: Database.Database,
  maxAgeDays: number = 90,
): number {
  const result = db
    .prepare(`
    DELETE FROM trajectories
    WHERE was_correct IS NULL
      AND created_at < datetime('now', ?)
  `)
    .run(`-${maxAgeDays} days`);

  return result.changes;
}
