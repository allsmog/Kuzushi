/**
 * Threat-model knowledge base — kind taxonomy + storage hookup.
 *
 * Operators stage architecture diagrams, RFCs, runbooks, audit reports, and
 * incident postmortems here so the Randori plugin sees them as untrusted
 * reference material when building the PASTA threat model.
 */

import {
  type AttachmentDocument,
  type AttachmentStorageAdapter,
  defaultAttachmentAdapter,
  type KindSpec,
} from "../_shared/attachments/index.js";

export type ThreatModelKind =
  | "design-doc"
  | "diagram"
  | "runbook"
  | "audit-report"
  | "runtime-log"
  | "incident"
  | "other";

export const THREAT_MODEL_KIND_SPEC: KindSpec<ThreatModelKind> = {
  moduleId: "threat-model",
  default: "other",
  kinds: ["design-doc", "diagram", "runbook", "audit-report", "runtime-log", "incident", "other"],
  inference: [
    { kind: "diagram", pattern: /\b(diagram|dfd|architecture|arch|flow|sequence)\b/ },
    { kind: "runbook", pattern: /\b(runbook|playbook|sop)\b/ },
    { kind: "audit-report", pattern: /\b(soc|iso|audit|pentest|pen-test|report)\b/ },
    { kind: "runtime-log", pattern: /\.log$|\b(metrics|trace|otel)\b/ },
    { kind: "incident", pattern: /\b(incident|postmortem|post-mortem|rca)\b/ },
    { kind: "design-doc", pattern: /\b(rfc|design|adr|spec)\b/ },
  ],
  label: (kind) => {
    switch (kind) {
      case "design-doc":
        return "design-doc";
      case "diagram":
        return "diagram";
      case "runbook":
        return "runbook";
      case "audit-report":
        return "audit-report";
      case "runtime-log":
        return "runtime-log";
      case "incident":
        return "incident";
      default:
        return "other";
    }
  },
};

/** Default storage adapter — `.kuzushi/threat-model/attachments.json`. */
export function threatModelAttachmentAdapter(): AttachmentStorageAdapter<ThreatModelKind> {
  return defaultAttachmentAdapter<ThreatModelKind>("threat-model");
}

/** Convenience loader — used by `threat-model:build` to read the persisted KB at run time. */
export function loadThreatModelAttachments(cwd: string): AttachmentDocument<ThreatModelKind>[] {
  return threatModelAttachmentAdapter().read(cwd);
}
