import { getBlameForLine } from "../../git/blame.js";
import type { MessageBus } from "../types.js";
import type { TriageResultEvent } from "../events.js";
import { updateFindingMetadata } from "../../store.js";
import type Database from "better-sqlite3";

export interface BlameWorkerDeps {
  db: Database.Database;
}

export function registerBlameWorker(
  bus: MessageBus,
  deps: BlameWorkerDeps,
): void {
  bus.subscribe<TriageResultEvent>("triage:result", (event) => {
    const { finding, result, context } = event.payload;

    // Only blame TP and needs_review findings
    if (result.verdict !== "tp" && result.verdict !== "needs_review") return;

    // Skip architectural findings with no specific file
    if (!finding.filePath || finding.filePath === ".") return;

    try {
      const blame = getBlameForLine(
        context.repoRoot,
        finding.filePath,
        finding.startLine,
      );

      if (blame) {
        updateFindingMetadata(deps.db, finding.fingerprint, {
          blame,
          introducedIn: blame.sha,
        });
      }
    } catch {
      // best-effort — don't fail the pipeline
    }
  });
}
