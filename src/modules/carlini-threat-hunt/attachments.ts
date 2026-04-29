/**
 * Threat-hunt knowledge base — kind taxonomy + storage hookup.
 *
 * Operators stage incident postmortems, runtime/SIEM logs, prior findings,
 * intel briefs, and hunt playbooks here so the per-actor hunt agents have
 * evidence beyond the codebase. The rendered block is injected between the
 * scope-restriction line and the actor's mission so the agent reads scope,
 * then evidence, then mission.
 */

import {
  type AttachmentDocument,
  type AttachmentStorageAdapter,
  defaultAttachmentAdapter,
  type KindSpec,
} from "../_shared/attachments/index.js";

export type CarliniThreatHuntKind =
  | "incident"
  | "runtime-log"
  | "prior-finding"
  | "intel-brief"
  | "siem-export"
  | "playbook"
  | "other";

export const CARLINI_THREAT_HUNT_KIND_SPEC: KindSpec<CarliniThreatHuntKind> = {
  moduleId: "carlini-threat-hunt",
  default: "other",
  kinds: [
    "incident",
    "runtime-log",
    "prior-finding",
    "intel-brief",
    "siem-export",
    "playbook",
    "other",
  ],
  inference: [
    { kind: "incident", pattern: /\b(incident|postmortem|post-mortem|rca)\b/ },
    { kind: "runtime-log", pattern: /\.log$|\b(splunk|datadog|otel|loki|cloudwatch)\b/ },
    { kind: "prior-finding", pattern: /\b(finding|vuln|cve|advisory)\b/ },
    { kind: "intel-brief", pattern: /\b(intel|ttp|ioc|brief)\b/ },
    { kind: "siem-export", pattern: /\b(siem|alert|export)\b/ },
    { kind: "playbook", pattern: /\b(playbook|hunt-plan|runbook)\b/ },
  ],
  label: (kind) => kind,
};

/** Default storage adapter — `.kuzushi/carlini-threat-hunt/attachments.json`. */
export function carliniThreatHuntAttachmentAdapter(): AttachmentStorageAdapter<CarliniThreatHuntKind> {
  return defaultAttachmentAdapter<CarliniThreatHuntKind>("carlini-threat-hunt");
}

/** Convenience loader — used by `carlini-threat-hunt:run` to seed the per-actor prompt. */
export function loadCarliniThreatHuntAttachments(
  cwd: string,
): AttachmentDocument<CarliniThreatHuntKind>[] {
  return carliniThreatHuntAttachmentAdapter().read(cwd);
}
