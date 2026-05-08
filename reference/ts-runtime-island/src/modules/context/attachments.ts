/**
 * Context module knowledge base — kind taxonomy + storage hookup.
 *
 * Operators stage architecture docs, API specs, runbooks, data dictionaries,
 * compliance policies, and prior incident reports here so the LLM context
 * enricher can ground its trust-boundary / data-classification analysis in
 * real artifacts rather than guessing from code alone.
 */

import {
  type AttachmentDocument,
  type AttachmentStorageAdapter,
  defaultAttachmentAdapter,
  type KindSpec,
} from "../_shared/attachments/index.js";

export type ContextKind =
  | "architecture-doc"
  | "api-spec"
  | "runbook"
  | "data-dictionary"
  | "compliance-policy"
  | "prior-incident"
  | "other";

export const CONTEXT_KIND_SPEC: KindSpec<ContextKind> = {
  moduleId: "context",
  default: "other",
  kinds: [
    "architecture-doc",
    "api-spec",
    "runbook",
    "data-dictionary",
    "compliance-policy",
    "prior-incident",
    "other",
  ],
  inference: [
    { kind: "api-spec", pattern: /\b(openapi|swagger|graphql|asyncapi|api-spec)\b/ },
    { kind: "data-dictionary", pattern: /\b(schema|erd|model|dictionary|datadict)\b/ },
    { kind: "compliance-policy", pattern: /\b(policy|privacy|gdpr|hipaa|soc2|sox|pci)\b/ },
    { kind: "prior-incident", pattern: /\b(incident|postmortem|post-mortem|rca)\b/ },
    { kind: "runbook", pattern: /\b(runbook|playbook|sop)\b/ },
    { kind: "architecture-doc", pattern: /\b(architecture|design|adr|rfc|spec)\b/ },
  ],
  label: (kind) => kind,
};

/** Default storage adapter — `.kuzushi/context/attachments.json`. */
export function contextAttachmentAdapter(): AttachmentStorageAdapter<ContextKind> {
  return defaultAttachmentAdapter<ContextKind>("context");
}

/** Convenience loader — used by the context-enricher task at run time. */
export function loadContextAttachments(cwd: string): AttachmentDocument<ContextKind>[] {
  return contextAttachmentAdapter().read(cwd);
}
