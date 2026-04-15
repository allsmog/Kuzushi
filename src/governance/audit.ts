/**
 * JSONL audit trail — records every tool execution for engagement compliance.
 * Appends one JSON line per action to a workspace-specific audit file.
 */

import { appendFileSync, mkdirSync, existsSync } from "node:fs";
import path from "node:path";
import type { AuditEntry } from "./types.js";

export class AuditTrail {
  private readonly logPath: string;

  /**
   * @param dataDir The .kuzushi data directory.
   * @param workspaceId Optional workspace ID for per-workspace audit files.
   */
  constructor(dataDir: string, workspaceId?: string) {
    const auditDir = path.join(dataDir, "audit");
    if (!existsSync(auditDir)) {
      mkdirSync(auditDir, { recursive: true });
    }

    const filename = workspaceId
      ? `audit-${workspaceId}.jsonl`
      : "audit-global.jsonl";
    this.logPath = path.join(auditDir, filename);
  }

  /** Append an audit entry to the log. */
  record(entry: AuditEntry): void {
    const line = JSON.stringify(entry) + "\n";
    appendFileSync(this.logPath, line, "utf-8");
  }

  /** Get the path to the audit log file. */
  getLogPath(): string {
    return this.logPath;
  }
}
